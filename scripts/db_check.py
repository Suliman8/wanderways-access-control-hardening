#!/usr/bin/env python3
"""Connect to the WanderWays SQLite database and prove that it works.

Opens the database read-only (it never creates or changes anything), prints
the SQLite version, an integrity check, every table with its row count, the
users per role and a sample of bookings, then verifies the lab baseline:
three roles (admin, agent, customer) and 20 bookings.

Usage:
    python scripts/db_check.py
    python scripts/db_check.py --db path/to/wanderways.db --output docs/evidence/db_connection_output.txt

Exit code 0 = connected and baseline OK, 1 = baseline mismatch, 2 = cannot connect.
"""
import argparse
import platform
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "instance" / "wanderways.db"
EXPECTED_ROLES = {"admin", "agent", "customer"}
EXPECTED_BOOKINGS = 20


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"database file (default: {DEFAULT_DB})")
    parser.add_argument("--output", type=Path, help="also save the report to this file")
    args = parser.parse_args()

    lines = []

    def out(text=""):
        print(text)
        lines.append(text)

    db_path = args.db.resolve()
    out("=" * 64)
    out(" WanderWays - database connection check")
    out("=" * 64)
    out(f"Run at        : {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    out(f"Python        : {platform.python_version()} ({platform.system()})")
    out(f"SQLite library: {sqlite3.sqlite_version}")
    out(f"Database file : {db_path}")

    if not db_path.is_file():
        out("\n[FAIL] Database file not found. Run:  flask --app wanderways init-db")
        save(args.output, lines)
        return 2

    try:
        # mode=ro -> read-only; fails instead of silently creating an empty file
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except sqlite3.Error as exc:
        out(f"\n[FAIL] Could not connect: {exc}")
        save(args.output, lines)
        return 2

    out(f"File size     : {db_path.stat().st_size:,} bytes")
    out(f"Integrity     : {integrity}")
    out("\n[OK] Connected to SQLite (read-only)\n")

    out("Tables")
    tables = [r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    for table in tables:
        count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        columns = [c["name"] for c in conn.execute(f'PRAGMA table_info("{table}")')]
        out(f"  {table:<10} {count:>3} rows   columns: {', '.join(columns)}")

    out("\nUsers by role")
    roles = {}
    for r in conn.execute("SELECT role, COUNT(*) AS n, GROUP_CONCAT(username, ', ') AS names"
                          " FROM users GROUP BY role ORDER BY role"):
        roles[r["role"]] = r["n"]
        out(f"  {r['role']:<9} {r['n']}  ({r['names']})")

    out("\nBookings by status")
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM bookings GROUP BY status ORDER BY n DESC"):
        out(f"  {r['status']:<10} {r['n']}")

    out("\nBookings per customer")
    for r in conn.execute("SELECT u.username, COUNT(b.id) AS n FROM users u"
                          " LEFT JOIN bookings b ON b.customer_id = u.id"
                          " WHERE u.role = 'customer' GROUP BY u.id ORDER BY u.id"):
        out(f"  {r['username']:<9} {r['n']}")

    out("\nSample bookings (first 5 of the table)")
    out(f"  {'id':>2}  {'ref':<10}  {'customer':<9}  {'destination':<24}  {'depart':<10}  {'status':<9}  total")
    for r in conn.execute("SELECT b.id, b.booking_ref, u.username, b.destination, b.depart_date, b.status,"
                          " b.total_price FROM bookings b JOIN users u ON u.id = b.customer_id"
                          " ORDER BY b.id LIMIT 5"):
        out(f"  {r['id']:>2}  {r['booking_ref']:<10}  {r['username']:<9}  {r['destination']:<24}  "
            f"{r['depart_date']:<10}  {r['status']:<9}  ${r['total_price']:,.2f}")

    total_bookings = conn.execute("SELECT COUNT(*) FROM bookings").fetchone()[0]
    conn.close()

    checks = [
        ("database integrity is 'ok'", integrity == "ok"),
        (f"roles present: {', '.join(sorted(EXPECTED_ROLES))}", EXPECTED_ROLES <= set(roles)),
        (f"{EXPECTED_BOOKINGS} sample bookings (found {total_bookings})", total_bookings == EXPECTED_BOOKINGS),
    ]
    out("\nBaseline checks")
    for label, passed in checks:
        out(f"  [{'PASS' if passed else 'FAIL'}] {label}")
    ok = all(passed for _, passed in checks)
    out(f"\nRESULT: {'PASS - database connection and seed data verified' if ok else 'FAIL - see above'}")
    if not ok:
        out("Hint: reset the lab data with  flask --app wanderways init-db")

    save(args.output, lines)
    return 0 if ok else 1


def save(path, lines):
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nSaved report to {path}")


if __name__ == "__main__":
    sys.exit(main())
