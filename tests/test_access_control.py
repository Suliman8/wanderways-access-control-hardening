"""Automated Access Control Test Suite (Task 3).

One test (or a small group) per Task 2 finding. Each asserts the attack is now
BLOCKED, and the matching legitimate action still WORKS. Run against the
hardened app this is all green; run against the `task2-vulnerable` tag and the
"blocked" assertions fail - which is exactly the point.

    python -m pytest tests/test_access_control.py -v

Accounts (from the deterministic seed):
    admin       id 1
    sara.agent  id 2   assigned a subset of bookings
    ayesha      id 4   customer, owns bookings 1, 5, 9, 13, 17
    omar        id 5   customer, owns bookings 2, 6, 10, 14, 18
"""
import sqlite3

import pytest

from wanderways import create_app

ACCOUNTS = {
    "admin": ("admin", "Admin@2026"),
    "agent": ("sara.agent", "Agent@2026"),
    "ayesha": ("ayesha", "Customer@2026"),
    "omar": ("omar", "Customer@2026"),
}
AYESHA_ID = 4
AYESHA_OWN_BOOKING = 1      # ayesha owns 1, 5, 9, 13, 17
OMAR_ID = 5
OMAR_BOOKING = 2              # omar owns 2, 6, 10, 14, 18 (the "victim" object)
OMAR_CONFIRMED_BOOKING = 6   # one of omar's that is 'confirmed' in the seed
BLOCKED = (401, 403, 404)   # any of these means the server refused access


@pytest.fixture()
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "ac.db")})


@pytest.fixture()
def login(app):
    """Return a factory: login('ayesha') -> a test client logged in as that account."""

    def factory(account=None):
        client = app.test_client()
        if account is not None:
            username, password = ACCOUNTS[account]
            assert client.post("/api/auth/login", json={"username": username, "password": password}).status_code == 200
        return client

    return factory


def db_value(app, sql, params=()):
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


# ===========================================================================
# WW-IDOR-01  Read any user's booking
# ===========================================================================

def test_idor01_customer_cannot_read_another_users_booking(login):
    r = login("ayesha").get(f"/api/bookings/{OMAR_BOOKING}")
    assert r.status_code in BLOCKED
    assert b"passport" not in r.data.lower()  # no PII leaked


def test_idor01_customer_can_still_read_their_own_booking(login):
    r = login("ayesha").get(f"/api/bookings/{AYESHA_OWN_BOOKING}")
    assert r.status_code == 200
    assert r.get_json()["customer_name"] == "Ayesha Khan"


def test_idor01_admin_can_read_any_booking(login):
    assert login("admin").get(f"/api/bookings/{OMAR_BOOKING}").status_code == 200


# ===========================================================================
# WW-IDOR-02  Modify / re-price / steal any booking
# ===========================================================================

def test_idor02_customer_cannot_modify_another_users_booking(login, app):
    before = db_value(app, "SELECT notes FROM bookings WHERE id = ?", (OMAR_BOOKING,))
    r = login("ayesha").put(f"/api/bookings/{OMAR_BOOKING}", json={"notes": "TAMPERED"})
    assert r.status_code in BLOCKED
    assert db_value(app, "SELECT notes FROM bookings WHERE id = ?", (OMAR_BOOKING,)) == before


def test_idor02_price_and_owner_are_not_client_settable_on_own_booking(login, app):
    before_price = db_value(app, "SELECT total_price FROM bookings WHERE id = ?", (AYESHA_OWN_BOOKING,))
    before_status = db_value(app, "SELECT status FROM bookings WHERE id = ?", (AYESHA_OWN_BOOKING,))
    r = login("ayesha").put(
        f"/api/bookings/{AYESHA_OWN_BOOKING}",
        json={"notes": "ok", "total_price": 0, "status": "confirmed", "customer_id": OMAR_ID},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["notes"] == "ok"                   # the allowed field was applied
    assert body["total_price"] == before_price      # client total_price=0 ignored (server-controlled)
    assert body["customer_id"] == AYESHA_ID          # ownership not transferred
    assert body["status"] == before_status           # a customer cannot change status


# ===========================================================================
# WW-IDOR-03  Cancel any user's booking
# ===========================================================================

def test_idor03_customer_cannot_cancel_another_users_booking(login, app):
    r = login("ayesha").post(f"/api/bookings/{OMAR_CONFIRMED_BOOKING}/cancel")
    assert r.status_code in BLOCKED
    # the victim's confirmed booking is untouched
    assert db_value(app, "SELECT status FROM bookings WHERE id = ?", (OMAR_CONFIRMED_BOOKING,)) == "confirmed"


def test_idor03_customer_can_cancel_their_own_booking(login):
    r = login("ayesha").post(f"/api/bookings/{AYESHA_OWN_BOOKING}/cancel")
    assert r.status_code == 200
    assert r.get_json()["status"] == "cancelled"


# ===========================================================================
# WW-BAC-04  Delete any booking as a non-admin
# ===========================================================================

def test_bac04_customer_cannot_delete_a_booking(login, app):
    r = login("ayesha").delete(f"/api/bookings/{AYESHA_OWN_BOOKING}")
    assert r.status_code in BLOCKED
    assert db_value(app, "SELECT COUNT(*) FROM bookings WHERE id = ?", (AYESHA_OWN_BOOKING,)) == 1


def test_bac04_agent_cannot_delete_a_booking(login):
    assert login("agent").delete(f"/api/bookings/{OMAR_BOOKING}").status_code in BLOCKED


def test_bac04_admin_can_delete_a_booking(login, app):
    assert login("admin").delete(f"/api/bookings/{OMAR_BOOKING}").status_code == 200
    assert db_value(app, "SELECT COUNT(*) FROM bookings WHERE id = ?", (OMAR_BOOKING,)) == 0


# ===========================================================================
# WW-IDOR-05  Read any account incl. password hash
# ===========================================================================

def test_idor05_customer_cannot_read_another_user(login):
    assert login("ayesha").get(f"/api/users/{OMAR_ID}").status_code in BLOCKED


def test_idor05_password_hash_is_never_returned(login):
    r = login("ayesha").get(f"/api/users/{AYESHA_ID}")  # own profile
    assert r.status_code == 200
    assert "password_hash" not in r.get_json()
    assert b"password_hash" not in r.data


# ===========================================================================
# WW-PRIV-06  Privilege escalation via self-service PATCH
# ===========================================================================

def test_priv06_customer_cannot_make_themselves_admin(login, app):
    client = login("ayesha")
    client.patch(f"/api/users/{AYESHA_ID}", json={"full_name": "Ayesha Khan", "role": "admin"})
    # role field is ignored for non-admins
    assert db_value(app, "SELECT role FROM users WHERE id = ?", (AYESHA_ID,)) == "customer"
    # and they still cannot reach an admin-only route
    assert client.get("/api/admin/stats").status_code == 403


def test_priv06_admin_can_change_a_role(login, app):
    r = login("admin").patch(f"/api/users/{OMAR_ID}", json={"role": "agent"})
    assert r.status_code == 200 and r.get_json()["role"] == "agent"


# ===========================================================================
# WW-BAC-07  Admin user directory exposed to non-admins
# ===========================================================================

@pytest.mark.parametrize("account", ["ayesha", "agent"])
def test_bac07_non_admin_cannot_list_users(login, account):
    assert login(account).get("/api/admin/users").status_code in BLOCKED


def test_bac07_admin_can_list_users(login):
    r = login("admin").get("/api/admin/users")
    assert r.status_code == 200 and r.get_json()["count"] == 7


# ===========================================================================
# WW-AUTH-08  Unauthenticated access to all bookings (legacy v1 API)
# ===========================================================================

@pytest.mark.parametrize("path", ["/api/v1/bookings", f"/api/v1/bookings/{OMAR_BOOKING}"])
def test_auth08_legacy_api_is_removed(login, path):
    assert login(None).get(path).status_code == 404      # anonymous
    assert login("ayesha").get(path).status_code == 404  # even when logged in


# ===========================================================================
# WW-AUTH-09  Secret-key disclosure enabling session forgery
# ===========================================================================

def test_auth09_debug_endpoint_is_removed(login):
    r = login(None).get("/api/internal/debug")
    assert r.status_code == 404
    assert b"secret" not in r.data.lower()


# ===========================================================================
# WW-BAC-10  Authorisation from a client-editable cookie (CSV export)
# ===========================================================================

def test_bac10_export_ignores_the_ww_role_cookie(login):
    client = login("ayesha")
    client.set_cookie("ww_role", "admin")  # the old forgery trick
    r = client.get("/api/admin/bookings/export")
    assert r.status_code == 403
    assert b"passport_no" not in r.data


def test_bac10_admin_can_export(login):
    r = login("admin").get("/api/admin/bookings/export")
    assert r.status_code == 200 and "passport_no" in r.get_data(as_text=True)


# ===========================================================================
# WW-MASS-11  Mass assignment on booking creation
# ===========================================================================

def test_mass11_create_ignores_privileged_fields(login):
    r = login("ayesha").post("/api/bookings", json={
        "destination": "Dubai, UAE", "depart_date": "2027-06-01", "return_date": "2027-06-05",
        "travellers": 2, "total_price": 0, "customer_id": OMAR_ID, "status": "confirmed",
    })
    assert r.status_code == 201
    body = r.get_json()
    assert body["total_price"] > 0            # server-computed, not the client's 0
    assert body["customer_id"] == AYESHA_ID    # owner is the caller, not the injected id
    assert body["status"] == "pending"         # not the injected 'confirmed'


# ===========================================================================
# Extra: the old ?customer_id= list override, and anonymous access
# ===========================================================================

def test_list_bookings_ignores_customer_id_override(login):
    data = login("ayesha").get(f"/api/bookings?customer_id={OMAR_ID}").get_json()
    assert data["count"] == 5
    assert {b["customer_name"] for b in data["bookings"]} == {"Ayesha Khan"}


@pytest.mark.parametrize("method,path", [
    ("get", "/api/bookings"), ("get", f"/api/bookings/{OMAR_BOOKING}"),
    ("get", f"/api/users/{AYESHA_ID}"), ("get", "/api/admin/users"),
])
def test_protected_routes_require_login(login, method, path):
    assert getattr(login(None), method)(path).status_code == 401
