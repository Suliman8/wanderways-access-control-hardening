# WanderWays Travel Portal — Access Control Hardening

A security engagement on a travel-booking app (**Python / Flask / SQLite**, roles: Admin, Agent,
Customer) for the Ezitech project **"Access Control Hardening for WanderWays Travel Portal"**. The app
began with insecure direct object references (IDOR) and broken role-based access control; this
repository **finds, exploits, fixes and verifies** all of them across three tasks.

| | |
|---|---|
| **Intern** | Suliman — Cyber Security |
| **Client** | Ezitech |
| **Tasks** | 1 Enumeration · 2 Exploitation · 3 Remediation & handover — **all done** |
| **Runs on** | `http://127.0.0.1:5000` (local lab) |
| **Outcome** | **11 access-control flaws found → 11 fixed → 42 automated tests passing (exploit re-run: 0/11)** |

> The app is now **hardened**. The exploitable version is preserved at the git tag `task2-vulnerable`
> for the before/after. It is still a local training lab — run it on `127.0.0.1` only.

## Start here

| If you want to… | Read |
|---|---|
| The full security story (found → exploited → fixed → verified) | **[`docs/SECURITY_REPORT.md`](docs/SECURITY_REPORT.md)** |
| Maintain the app safely (the authorization middleware, running tests) | **[`docs/HANDOVER.md`](docs/HANDOVER.md)** |
| How each flaw was exploited (PoC + impact) | [`docs/findings_task2.md`](docs/findings_task2.md) |
| The endpoint map | [`docs/api_endpoints.txt`](docs/api_endpoints.txt) |
| Run it yourself | [Local setup](#local-setup) |

## The three tasks (mentor deliverables)

**Task 1 — Lab setup & baseline enumeration.** 25 endpoints mapped (5 hidden) in
[`docs/api_endpoints.txt`](docs/api_endpoints.txt); DB connection proven by
[`scripts/db_check.py`](scripts/db_check.py); Burp + ffuf traffic mapping in
[`docs/proxy_mapping.md`](docs/proxy_mapping.md).

**Task 2 — Exploiting IDOR & broken access control.** 11/11 flaws confirmed by live exploitation
(2 Critical, 7 High, 2 Medium). Reproducible PoC [`exploit/exploit_idor.py`](exploit/exploit_idor.py),
full HTTP log [`docs/evidence/task2/exploit_log.txt`](docs/evidence/task2/exploit_log.txt), report
[`docs/findings_task2.md`](docs/findings_task2.md).

**Task 3 — Remediation & handover.** Central authorization middleware
[`wanderways/authz.py`](wanderways/authz.py); automated access-control test suite
[`tests/test_access_control.py`](tests/test_access_control.py) (28 tests); final report
[`docs/SECURITY_REPORT.md`](docs/SECURITY_REPORT.md) and handover
[`docs/HANDOVER.md`](docs/HANDOVER.md).

```bash
# prove it: 42 tests pass, and the original exploit now finds nothing
python -m pytest -q                                    # 42 passed
flask --app wanderways init-db && flask --app wanderways run &   # start app
python exploit/exploit_idor.py                         # 0/11 vulnerable
flask --app wanderways init-db                         # reset the lab
```

---

## Task 1 reference (endpoint enumeration)

| Requirement | Where to find it |
|---|---|
| README documenting the local setup steps | This file → [Local setup](#local-setup) |
| List of all discovered API endpoints and their HTTP methods | [`docs/api_endpoints.txt`](docs/api_endpoints.txt) – 25 endpoints, 30 method + path pairs |
| Evidence of a successful connection to the local database using a script | [`scripts/db_check.py`](scripts/db_check.py) → output in [`docs/evidence/db_connection_output.txt`](docs/evidence/db_connection_output.txt) |
| Python virtual environment with Flask | [Step 2–3](#2-create-and-activate-a-virtual-environment), [`requirements.txt`](requirements.txt) |
| Booking system with Admin, Agent and Customer roles and 20 bookings | [`wanderways/`](wanderways), seed data in [`wanderways/seed.py`](wanderways/seed.py) |
| Proxy used to map all traffic and find hidden endpoints | [`docs/proxy_mapping.md`](docs/proxy_mapping.md), Burp Suite site map [`burp_sitemap.png`](docs/evidence/screenshots/burp_sitemap.png), full capture in [`docs/evidence/proxy/`](docs/evidence/proxy) |
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
│   ├── auth.py                  #   login / logout / sessions (no client role cookie)
│   ├── authz.py                 #   ★ Task 3: central authorization middleware
│   ├── views.py                 #   HTML pages, robots.txt, /health
│   ├── api.py                   #   booking + user REST API (authorised per object)
│   ├── admin.py                 #   admin API (admin-only, server-side role)
│   ├── templates/  static/      #   pages, CSS, front-end JavaScript
├── scripts/
│   ├── db_check.py              # proves the database connection (Task 1)
│   └── generate_traffic.py      # replays every role's journey through a proxy
├── recon/                       # Task 1: black-box enumeration
│   ├── enumerate_endpoints.py   # black-box endpoint + HTTP method discovery
│   ├── har_sitemap.py           # proxy capture (HAR) -> history + site map
│   └── wordlist.txt             # 90-word API wordlist
├── exploit/                     # Task 2: IDOR & broken access control PoC
│   ├── exploit_idor.py          # runs all 11 findings, writes the evidence
│   ├── wwclient.py              # HTTP client that logs every request/response
│   └── wanderways_idor.postman_collection.json
├── tests/
│   ├── test_lab_setup.py        # setup smoke tests (14)
│   └── test_access_control.py   # ★ Task 3: access-control test suite (28)
├── docs/
│   ├── SECURITY_REPORT.md       # ★ Task 3 FINAL REPORT (vulnerability lifecycle)
│   ├── HANDOVER.md              # ★ Task 3 HANDOVER (middleware + running tests)
│   ├── findings_task2.md        # Task 2 vulnerability report
│   ├── api_endpoints.txt        # Task 1 endpoint list
│   ├── proxy_mapping.md         # Task 1 Burp Suite step-by-step
│   ├── task2_burp_walkthrough.md# Task 2 reproduce the IDOR by hand
│   └── evidence/                # outputs & logs for Tasks 1, 2, 3 (incl. after_fix)
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
pytest -q                         # 14 passed
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

### Enforced access rules

These rules are now enforced centrally in [`wanderways/authz.py`](wanderways/authz.py) and covered by
`tests/test_access_control.py`.

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
| 1. Lab setup and baseline enumeration | 2 | **Done** — `docs/api_endpoints.txt` |
| 2. Exploiting IDOR and broken access control | 2 | **Done** — `docs/findings_task2.md`, 11/11 vulnerable |
| 3. Remediation, test suite, report & handover | 1 | **Done** — `docs/SECURITY_REPORT.md`, 11/11 fixed |

The exploitable version (before remediation) is preserved at the git tag `task2-vulnerable`:
`git checkout task2-vulnerable` for the vulnerable app, `git checkout main` for the hardened one.

## Scope and safety

All testing happened on the author's own machine against this local app. The recon and exploit scripts
refuse non-localhost targets. The data (names, emails, passport numbers, card digits) is fictional. The
app is now hardened; keep it on `127.0.0.1` and set `WANDERWAYS_SECRET_KEY` before any real deployment
(see [`docs/HANDOVER.md`](docs/HANDOVER.md)).
