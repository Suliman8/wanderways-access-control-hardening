"""Smoke tests: the lab installs, seeds and serves correctly.

These check the Task 1 setup only. The access-control test suite (which is
expected to FAIL until the Task 3 fixes land) is a later deliverable.

Run:  python -m pytest -q
"""
import sqlite3

import pytest

from wanderways import create_app

ACCOUNTS = {
    "admin": ("admin", "Admin@2026"),
    "agent": ("sara.agent", "Agent@2026"),
    "customer": ("ayesha", "Customer@2026"),
}


@pytest.fixture()
def app(tmp_path):
    return create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db")})


@pytest.fixture()
def client(app):
    return app.test_client()


def query(app, sql):
    conn = sqlite3.connect(app.config["DATABASE"])
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_database_is_seeded_with_three_roles_and_20_bookings(app):
    roles = {role for (role,) in query(app, "SELECT DISTINCT role FROM users")}
    assert roles == {"admin", "agent", "customer"}
    assert query(app, "SELECT COUNT(*) FROM bookings")[0][0] == 20


def test_every_booking_belongs_to_a_customer_and_an_agent(app):
    orphans = query(app, """
        SELECT b.id FROM bookings b
        LEFT JOIN users c ON c.id = b.customer_id AND c.role = 'customer'
        LEFT JOIN users a ON a.id = b.agent_id AND a.role = 'agent'
        WHERE c.id IS NULL OR a.id IS NULL
    """)
    assert orphans == []


def test_seed_data_is_deterministic(tmp_path):
    first = create_app({"DATABASE": str(tmp_path / "a.db")})
    second = create_app({"DATABASE": str(tmp_path / "b.db")})
    sql = "SELECT booking_ref, customer_id, destination, depart_date, total_price, status FROM bookings ORDER BY id"
    assert query(first, sql) == query(second, sql)


def test_init_db_cli_resets_the_data(app):
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0
    assert "bookings: 20" in result.output


def test_health_endpoint_reports_database_connected(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["database"] == "connected"


@pytest.mark.parametrize("role", ACCOUNTS)
def test_each_role_can_log_in(client, role):
    username, password = ACCOUNTS[role]
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    assert response.get_json()["user"]["role"] == role
    assert client.get("/api/auth/me").get_json()["username"] == username


def test_wrong_password_is_rejected(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert response.status_code == 401


def test_non_object_json_body_is_rejected_cleanly(client):
    response = client.post("/api/auth/login", json=["admin", "Admin@2026"])
    assert response.status_code == 401


def test_api_requires_login(client):
    assert client.get("/api/bookings").status_code == 401


def test_pages_redirect_to_login_when_anonymous(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_customer_dashboard_lists_only_their_five_bookings(client):
    client.post("/api/auth/login", json={"username": "ayesha", "password": "Customer@2026"})
    data = client.get("/api/bookings").get_json()
    assert data["count"] == 5
    assert {b["customer_name"] for b in data["bookings"]} == {"Ayesha Khan"}


def test_options_reports_allowed_methods(client):
    allow = client.options("/api/bookings/1").headers["Allow"]
    assert {"GET", "PUT", "DELETE"} <= {m.strip() for m in allow.split(",")}
