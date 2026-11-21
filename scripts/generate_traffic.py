#!/usr/bin/env python3
"""Replay normal user journeys through an intercepting proxy (Burp Suite / mitmproxy).

Each role (anonymous, customer, agent, admin) clicks through the same pages a
real user would - including the JavaScript API calls - so the proxy's site
map / HTTP history fills up with every endpoint the UI uses.

Usage:
    python scripts/generate_traffic.py --proxy http://127.0.0.1:8081
    python scripts/generate_traffic.py --proxy http://127.0.0.1:8081 --with-writes

By default only reads are sent. --with-writes also creates, edits and cancels
one new booking and re-saves the customer's profile (so POST/PUT/PATCH appear
in the proxy too). It adds a 21st booking - reset afterwards with
    flask --app wanderways init-db
"""
import argparse
import sys

import requests

ACCOUNTS = {
    "customer": ("ayesha", "Customer@2026"),
    "agent": ("sara.agent", "Agent@2026"),
    "admin": ("admin", "Admin@2026"),
}
ASSETS = ["/static/css/style.css", "/static/js/app.js"]


class Browser:
    """A requests.Session that logs every request it sends."""

    def __init__(self, base, proxy, label):
        self.base = base.rstrip("/")
        self.label = label
        self.session = requests.Session()
        self.session.trust_env = False  # ignore NO_PROXY so localhost goes through the proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers["User-Agent"] = "WanderWays-traffic-generator/1.0 (lab)"
        self.count = 0

    def send(self, method, path, **kwargs):
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("allow_redirects", False)
        response = self.session.request(method, self.base + path, **kwargs)
        self.count += 1
        print(f"  [{self.label:<9}] {method:<6} {path:<34} -> {response.status_code}")
        return response

    def page(self, path):
        """Load an HTML page plus its CSS/JS, like a browser would."""
        response = self.send("GET", path)
        if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
            for asset in ASSETS:
                self.send("GET", asset)
        return response


def anonymous_journey(base, proxy):
    b = Browser(base, proxy, "anonymous")
    b.send("GET", "/")                                 # -> 302 to /login
    b.page("/login")
    b.send("GET", "/dashboard")                        # -> 302 to /login?next=/dashboard
    b.send("POST", "/api/auth/login", json={"username": "ayesha", "password": "wrong"})  # mistyped password
    return b.count


def user_journey(base, proxy, role, with_writes):
    username, password = ACCOUNTS[role]
    b = Browser(base, proxy, role)
    b.page("/login")
    login = b.send("POST", "/api/auth/login", json={"username": username, "password": password})
    if login.status_code != 200:
        sys.exit(f"Login failed for {username}: HTTP {login.status_code}")
    user_id = login.json()["user"]["id"]

    b.page("/dashboard")
    bookings = b.send("GET", "/api/bookings").json()["bookings"]

    if bookings:
        first = bookings[0]["id"]
        b.page(f"/bookings/{first}")
        b.send("GET", f"/api/bookings/{first}")

    b.page("/profile")
    profile = b.send("GET", f"/api/users/{user_id}").json()

    if role == "customer":
        b.page("/bookings/new")
        b.send("GET", "/api/destinations")
        b.send("GET", "/api/agents")
        if with_writes:
            new = b.send("POST", "/api/bookings", json={
                "destination": "Skardu, Pakistan", "hotel": "Shangrila Lakeside",
                "depart_date": "2027-04-10", "return_date": "2027-04-15",
                "travellers": 2, "agent_id": None, "notes": "Created by traffic generator",
            }).json()
            b.page(f"/bookings/{new['id']}")
            b.send("GET", f"/api/bookings/{new['id']}")
            b.send("PUT", f"/api/bookings/{new['id']}", json={
                "depart_date": "2027-04-11", "return_date": "2027-04-16", "travellers": 2,
                "notes": "Dates moved by one day",
            })
            b.send("POST", f"/api/bookings/{new['id']}/cancel")
            b.send("PATCH", f"/api/users/{user_id}", json={
                "full_name": profile["full_name"], "email": profile["email"], "phone": profile["phone"],
            })

    if role == "admin":
        b.page("/admin")
        b.send("GET", "/api/admin/stats")
        b.send("GET", "/api/admin/users")
        b.send("GET", "/api/admin/bookings/export")

    b.send("POST", "/api/auth/logout")
    return b.count


def main():
    parser = argparse.ArgumentParser(description="Generate realistic WanderWays traffic through a proxy.")
    parser.add_argument("--base", default="http://127.0.0.1:5000", help="app URL (default: %(default)s)")
    parser.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8081 (Burp/mitmproxy listener)")
    parser.add_argument("--with-writes", action="store_true", help="also send POST/PUT/PATCH (adds a booking)")
    args = parser.parse_args()

    print(f"Target: {args.base}   Proxy: {args.proxy or 'none (direct)'}\n")
    try:
        total = anonymous_journey(args.base, args.proxy)
        for role in ("customer", "agent", "admin"):
            total += user_journey(args.base, args.proxy, role, args.with_writes)
    except requests.ConnectionError as exc:
        sys.exit(f"Connection failed - is the app (and the proxy) running?\n{exc}")
    print(f"\nDone: {total} requests sent.")
    if args.with_writes:
        print("A test booking was added. Reset with:  flask --app wanderways init-db")


if __name__ == "__main__":
    main()
