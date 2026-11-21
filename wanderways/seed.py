"""Deterministic sample data: 7 users in 3 roles and 20 bookings.

A fixed random seed means every machine gets exactly the same records,
so endpoint IDs and test results can be reproduced. All people, passport
numbers and card digits are fictional.
"""
import random
from datetime import date, datetime, timedelta

from werkzeug.security import generate_password_hash

RANDOM_SEED = 2026
BOOKING_COUNT = 20

# username, password, full name, email, phone, role
USERS = [
    ("admin", "Admin@2026", "Areeba Siddiqui", "admin@wanderways.test", "+92-300-5550101", "admin"),
    ("sara.agent", "Agent@2026", "Sara Malik", "sara.malik@wanderways.test", "+92-300-5550102", "agent"),
    ("bilal.agent", "Agent@2026", "Bilal Ahmed", "bilal.ahmed@wanderways.test", "+92-300-5550103", "agent"),
    ("ayesha", "Customer@2026", "Ayesha Khan", "ayesha.khan@example.test", "+92-321-5550104", "customer"),
    ("omar", "Customer@2026", "Omar Farooq", "omar.farooq@example.test", "+92-321-5550105", "customer"),
    ("hina", "Customer@2026", "Hina Raza", "hina.raza@example.test", "+92-321-5550106", "customer"),
    ("usman", "Customer@2026", "Usman Tariq", "usman.tariq@example.test", "+92-321-5550107", "customer"),
]

# destination -> (price per traveller in USD, hotels)
DESTINATIONS = {
    "Dubai, UAE": (650, ["Marina Bay Suites", "Creekside Grand"]),
    "Istanbul, Turkiye": (720, ["Bosphorus View Hotel", "Old City Inn"]),
    "Baku, Azerbaijan": (540, ["Caspian Pearl", "Flame Towers Residence"]),
    "Kuala Lumpur, Malaysia": (810, ["Petronas Park Hotel", "Bukit Bintang Lodge"]),
    "Hunza Valley, Pakistan": (300, ["Karimabad Heights", "Attabad Lake Resort"]),
    "Skardu, Pakistan": (280, ["Shangrila Lakeside", "Deosai Base Camp"]),
    "Bangkok, Thailand": (760, ["Riverside Orchid", "Sukhumvit Central"]),
    "London, United Kingdom": (1450, ["Thames Court Hotel", "Paddington Rooms"]),
    "Tbilisi, Georgia": (590, ["Old Tbilisi Boutique", "Rustaveli Plaza"]),
}

NOTES = [
    "",
    "Window seat requested",
    "Vegetarian meals",
    "Airport pickup needed",
    "Honeymoon package",
    "Late check-out requested",
    "Travelling with an infant",
]


def seed_database(conn):
    """Insert users and bookings. Expects freshly created, empty tables."""
    rng = random.Random(RANDOM_SEED)

    for username, password, full_name, email, phone, role in USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, email, phone, role, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), full_name, email, phone, role, "2026-11-01 09:00:00"),
        )

    ids_by_role = {"admin": [], "agent": [], "customer": []}
    for row in conn.execute("SELECT id, role FROM users ORDER BY id"):
        ids_by_role[row["role"]].append(row["id"])
    customers, agents = ids_by_role["customer"], ids_by_role["agent"]

    first_departure = date(2026, 12, 1)
    for i in range(BOOKING_COUNT):
        destination = rng.choice(list(DESTINATIONS))
        price_per_traveller, hotels = DESTINATIONS[destination]
        depart = first_departure + timedelta(days=rng.randint(0, 110))
        nights = rng.randint(3, 10)
        travellers = rng.randint(1, 4)
        nightly_rate = rng.choice([70, 95, 120, 160])
        created = datetime(2026, 11, 1, 9, 0) + timedelta(days=rng.randint(0, 19), minutes=rng.randint(0, 600))
        conn.execute(
            "INSERT INTO bookings (booking_ref, customer_id, agent_id, destination, hotel, depart_date,"
            " return_date, travellers, total_price, status, passport_no, payment_last4, notes, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"WW-26-{1001 + i}",
                customers[i % len(customers)],  # 5 bookings per customer
                rng.choice(agents),
                destination,
                rng.choice(hotels),
                depart.isoformat(),
                (depart + timedelta(days=nights)).isoformat(),
                travellers,
                float(price_per_traveller * travellers + nightly_rate * nights),
                rng.choices(["confirmed", "pending", "cancelled"], weights=[6, 3, 1])[0],
                f"ZX{rng.randint(1000000, 9999999)}",
                f"{rng.randint(0, 9999):04d}",
                rng.choice(NOTES),
                created.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
    conn.commit()

    roles = {r["role"]: r["n"] for r in conn.execute("SELECT role, COUNT(*) AS n FROM users GROUP BY role ORDER BY role")}
    return {
        "users": sum(roles.values()),
        "roles": roles,
        "bookings": conn.execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
    }
