# WanderWays Travel Portal – Access Control Lab

> **Warning:** this is an **intentionally vulnerable** training app. It has broken access control
> on purpose. Run it only on your own machine (`127.0.0.1`). Never deploy it or expose it to a network.

WanderWays is a small travel booking prototype built with **Python, Flask and SQLite** for the Ezitech
project **"Access Control Hardening for WanderWays Travel Portal"**. It has three user roles
(**Admin, Agent, Customer**) and 20 sample bookings. It also contains insecure direct object references
(IDOR) and broken role checks, so they can be found, exploited and fixed across the three project tasks.

This repository currently delivers **Task 1 – Lab Setup and Baseline Enumeration**.

| | |
|---|---|
| **Intern** | Suliman – Cyber Security |
| **Client** | Ezitech |
| **Task 1** | 20–21 Nov 2026 |
| **Runs on** | `http://127.0.0.1:5000` |

---

## Task 1 checklist (what the mentor checks)

| Requirement | Where to find it |
|---|---|
| README documenting the local setup steps | This file → [Local setup](#local-setup) |
| List of all discovered API endpoints and their HTTP methods | [`docs/api_endpoints.txt`](docs/api_endpoints.txt) – 25 endpoints, 30 method + path pairs |
| Evidence of a successful connection to the local database using a script | [`scripts/db_check.py`](scripts/db_check.py) → output in [`docs/evidence/db_connection_output.txt`](docs/evidence/db_connection_output.txt) |
| Python virtual environment with Flask | [Step 2–3](#2-create-and-activate-a-virtual-environment), [`requirements.txt`](requirements.txt) |
| Booking system with Admin, Agent and Customer roles and 20 bookings | [`wanderways/`](wanderways), seed data in [`wanderways/seed.py`](wanderways/seed.py) |
| Proxy used to map all traffic and find hidden endpoints | [`docs/proxy_mapping.md`](docs/proxy_mapping.md), capture in [`docs/evidence/proxy/`](docs/evidence/proxy) |
| App running on localhost:5000 | [`docs/evidence/screenshots/`](docs/evidence/screenshots) |

---

## Tech stack

| Purpose | Tool |
|---|---|
| Web app | Python 3 + Flask 3.1 |
| Database | SQLite (built into Python, file at `instance/wanderways.db`) |
| Proxy / traffic mapping | Burp Suite Community (mitmproxy used for the saved capture) |
| Fuzzing | ffuf + `recon/enumerate_endpoints.py` (own script) |
| Tests | pytest |

## Repository layout

```
wanderways-access-control-hardening/
├── wanderways/                  # the Flask application
│   ├── __init__.py              #   app factory (create_app)
│   ├── db.py                    #   SQLite connection + `init-db` command
│   ├── schema.sql               #   tables: users, bookings
│   ├── seed.py                  #   7 users in 3 roles + 20 bookings (fixed random seed)
│   ├── auth.py                  #   login / logout / sessions
│   ├── views.py                 #   HTML pages, robots.txt, /health
│   ├── api.py                   #   booking + user REST API
│   ├── admin.py                 #   admin API
│   ├── legacy.py                #   old endpoints that were never removed (hidden)
│   ├── templates/  static/      #   pages, CSS, front-end JavaScript
├── scripts/
│   ├── db_check.py              # proves the database connection (mentor check)
│   └── generate_traffic.py      # replays every role's journey through a proxy
├── recon/
│   ├── enumerate_endpoints.py   # black-box endpoint + HTTP method discovery
│   ├── har_sitemap.py           # proxy capture (HAR) -> history + site map
│   └── wordlist.txt             # 90-word API wordlist
├── docs/
│   ├── api_endpoints.txt        # ENDPOINT LIST (mentor check)
│   ├── proxy_mapping.md         # Burp Suite step-by-step
│   └── evidence/                # outputs, proxy capture, screenshots
├── tests/test_lab_setup.py      # setup smoke tests (13 tests)
├── requirements.txt
└── pytest.ini
```

---

## Local setup

Tested on Kali Linux with Python 3.13.12. Any OS with **Python 3.10 or newer** and **Git** will work.
Run every command from the repository folder.

### 1. Clone the repository

```bash
git clone https://github.com/Suliman8/wanderways-access-control-hardening.git
cd wanderways-access-control-hardening
```

### 2. Create and activate a virtual environment

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

(If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
In `cmd.exe` use `.venv\Scripts\activate.bat`.)

After this your prompt starts with `(.venv)`.

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

This installs Flask 3.1.3, requests 2.34.2 and pytest 9.2.0 (exact versions, so every machine is the same).

### 4. Create the database

```bash
flask --app wanderways init-db
```

Expected output:

```
Database ready: .../instance/wanderways.db
  users:    7  {'admin': 1, 'agent': 2, 'customer': 4}
  bookings: 20
```

Running this command again resets the lab to the original 20 bookings at any time.

### 5. Start the app

```bash
flask --app wanderways run
```

Open **http://127.0.0.1:5000** and sign in with one of the [demo accounts](#demo-accounts).
`flask run` listens on `127.0.0.1` by default. Do **not** add `--host 0.0.0.0`.

### 6. Check that everything works

Open a second terminal, activate the venv again (step 2), then:

```bash
python scripts/db_check.py        # database connection check -> must end with "RESULT: PASS"
curl http://127.0.0.1:5000/health # {"status":"ok","service":"wanderways","database":"connected"}
pytest -q                         # 13 passed
```

`db_check.py` opens `instance/wanderways.db` **read-only**. It prints the SQLite version, an integrity
check, every table with its row count, the users per role and a sample of bookings, then checks that
3 roles and 20 bookings exist. Use `--output <file>` to save the report. A saved run is in
[`docs/evidence/db_connection_output.txt`](docs/evidence/db_connection_output.txt):

```
[OK] Connected to SQLite (read-only)
...
Baseline checks
  [PASS] database integrity is 'ok'
  [PASS] roles present: admin, agent, customer
  [PASS] 20 sample bookings (found 20)

RESULT: PASS - database connection and seed data verified
```

---

## Demo accounts

Lab-only passwords. The data is fictional.

| Role | Username | Password | Bookings |
|---|---|---|---|
| Admin | `admin` | `Admin@2026` | sees all 20 |
| Agent | `sara.agent` | `Agent@2026` | 10 assigned |
| Agent | `bilal.agent` | `Agent@2026` | 10 assigned |
| Customer | `ayesha` | `Customer@2026` | 5 own |
| Customer | `omar` | `Customer@2026` | 5 own |
| Customer | `hina` | `Customer@2026` | 5 own |
| Customer | `usman` | `Customer@2026` | 5 own |

The 20 bookings are generated with a fixed random seed (`wanderways/seed.py`), so IDs, prices and
dates are identical on every machine. Each booking stores sensitive fields (passport number,
card last 4 digits) to make data leaks easy to see.

### Intended access rules

Task 2 tests these rules and Task 3 enforces them.

| Action | Customer | Agent | Admin |
|---|---|---|---|
| View bookings | own only | assigned to them | all |
| Create booking | for themself | – | yes |
| Change booking | own (dates, travellers, notes) | assigned (status) | yes |
| Cancel booking | own | – | yes |
| Delete booking | – | – | yes |
| View / edit profile | own (not role) | own (not role) | all, incl. roles |
| Admin pages and API | – | – | yes |

---

## Mapping the API (how Task 1 was done)

The app was mapped **black-box first**, the way an outside tester would, and then compared with the
source code to prove nothing was missed.

1. **Proxy (passive).** All traffic went through an intercepting proxy on `127.0.0.1:8081` while
   logging in as every role and using every page. Burp steps are in [`docs/proxy_mapping.md`](docs/proxy_mapping.md).
   To replay the same journeys automatically:
   ```bash
   python scripts/generate_traffic.py --proxy http://127.0.0.1:8081
   ```
   Result: 18 paths ([site map](docs/evidence/proxy/proxy_sitemap.txt), [HTTP history](docs/evidence/proxy/proxy_history.txt)).
2. **Active discovery.** robots.txt, JavaScript review, wordlist fuzzing, ID probing and `OPTIONS`
   requests (the `Allow` header lists each endpoint's HTTP methods):
   ```bash
   python recon/enumerate_endpoints.py --routes docs/evidence/flask_routes.txt --out docs/evidence
   ffuf -u http://127.0.0.1:5000/api/FUZZ -w recon/wordlist.txt -ic -mc 200,204,301,302,307,401,403,405
   ```
   It sends only GET, HEAD and OPTIONS, so no data changes. It also refuses any target that is not localhost.
3. **Verification.** `flask --app wanderways routes` lists the real routes
   ([saved](docs/evidence/flask_routes.txt)). The black-box scan found **25/25 paths and every method,
   with no false positives**.

**Result:** 25 endpoints, 30 method + path pairs. The proxy saw 18 of them. Of the 7 it never saw,
**5 are hidden** because no link or code in the UI points to them:

| Hidden endpoint | How it was found |
|---|---|
| `GET /api/v1/bookings` | developer comment in `app.js`, confirmed with ffuf |
| `GET /api/v1/bookings/{id}` | ID probing |
| `GET /api/internal/debug` | `robots.txt` (`/api/internal/`) + wordlist |
| `GET /api/auth/me` | wordlist |
| `GET /health` | wordlist |

The other two the proxy did not see are `GET /logout` (an HTML link, but the UI logs out through the API)
and `GET /robots.txt` (standard file). `DELETE /api/bookings/{id}` was found only through `OPTIONS`,
because the UI has no delete button.

**Full list with methods, access matrix and first observations: [`docs/api_endpoints.txt`](docs/api_endpoints.txt).**

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `no such table: users` | Run `flask --app wanderways init-db` |
| Port 5000 already in use (macOS: AirPlay Receiver) | `flask --app wanderways run --port 5001` and use that port in the scripts (`--base`) |
| Burp will not start its listener on 8080 | Another program uses 8080. Set the listener to `127.0.0.1:8081` (see `docs/proxy_mapping.md`) |
| Firefox traffic to 127.0.0.1 does not show in Burp | In `about:config` set `network.proxy.allow_hijacking_localhost` to `true`, or use Burp's built-in browser |
| `flask: command not found` | The venv is not active. Repeat step 2 |
| Bookings count is not 20 (after testing writes) | `flask --app wanderways init-db` |

## Project roadmap

| Task | Days | Status |
|---|---|---|
| 1. Lab setup and baseline enumeration | 2 | **Done** (this repository) |
| 2. Exploiting IDOR and broken access control | 2 | Next |
| 3. Final security report and handover (fixes, automated access-control tests, handover doc) | 1 | Planned |

Every intentional weakness is marked with a `LAB-VULN` comment in the code. This keeps the Task 3
patch set easy to review.

## Scope and safety

All testing happened on the author's own machine against this local app. The recon script refuses
non-localhost targets. The data (names, emails, passport numbers, card digits) is fictional.
