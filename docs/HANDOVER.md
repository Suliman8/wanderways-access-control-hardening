# WanderWays — Security Handover Document

For the next developer who maintains WanderWays. It explains the authorization middleware added during
the access-control hardening, how to run the test suite, and the rules to keep the app secure when you
add features.

**Golden rule:** authorization is centralised in [`wanderways/authz.py`](../wanderways/authz.py). Do not
re-implement access checks inside routes — call the helpers. Every new endpoint needs a test in
`tests/test_access_control.py`.

---

## 1. The authorization middleware (`wanderways/authz.py`)

The access policy:

| Role | Bookings it may act on | Profile it may edit |
|---|---|---|
| **admin** | all — view / update / cancel / delete / reassign | anyone, including the `role` field |
| **agent** | only bookings **assigned to them** — view / update / cancel (no delete) | their own (never `role`) |
| **customer** | only their **own** bookings — view / update / cancel (no delete) | their own (never `role`) |

Four building blocks:

| Helper | Use it for | Returns |
|---|---|---|
| `role_required(*roles)` | function-level: lock an endpoint to role(s) | decorator (401 / 403) |
| `admin_required` | shorthand for `role_required("admin")` | decorator |
| `can_access_booking(booking, action, user)` | object-level: ownership of one booking | `True` / `False` |
| `can_access_user(target_id, user)` | object-level: own profile or admin | `True` / `False` |
| `public_user(row)` | strip sensitive fields (never returns `password_hash`) | dict |

In the booking routes the object check is wrapped in one helper,
`load_booking_or_error(id, action)` (in `wanderways/api.py`), which returns the booking **or** a ready
`(response, status)` — `404` if it does not exist, `403` if it exists but the caller may not touch it.

---

## 2. How to add a new endpoint securely

**A booking (or other owned object) route — needs an object-level check:**

```python
@bp.get("/bookings/<int:booking_id>/receipt")
@login_required
def booking_receipt(booking_id):
    booking, err = load_booking_or_error(booking_id, "view")   # ownership enforced here
    if err:
        return err
    return jsonify(...)
```

**An admin-only route — needs a function-level check:**

```python
@bp.get("/api/admin/report")
@admin_required                 # role comes from the server-side session, never a cookie
def admin_report():
    return jsonify(...)
```

**Accepting data from the client — use an allow-list, never the raw body:**

```python
ALLOWED = {"destination", "hotel", "notes"}     # never "role", "total_price", "status", "customer_id"
changes = {k: data[k] for k in ALLOWED if k in data}
```

Set privileged values (price, status, owner, role) on the **server**, computed or from the session user.

**Returning a user record** — always go through `public_user(row)` so the password hash cannot leak.

### Checklist for every new endpoint
- [ ] `@login_required` (or `@admin_required`) is present.
- [ ] For a `/{id}` route, ownership is checked with `load_booking_or_error` / `can_access_user`.
- [ ] The request body is filtered through an allow-list; no privileged field is mass-assigned.
- [ ] Any user data in the response goes through `public_user`.
- [ ] A test was added to `tests/test_access_control.py` (one "attack blocked", one "legit works").

---

## 3. Running the automated access-control test suite

```bash
# one-time setup
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# run every test (42: 14 setup + 28 access-control)
python -m pytest -q

# only the access-control suite, verbose
python -m pytest tests/test_access_control.py -v
```

Expected: **42 passed**. Each access-control test maps to a finding ID (e.g. `test_idor01_*`,
`test_priv06_*`). A saved run is in [`evidence/task3/test_results.txt`](evidence/task3/test_results.txt).

**Regression proof (optional):** the suite is designed so that if a future change re-introduces a flaw,
the matching test fails. To see the suite catch the original vulnerabilities, run the *current* tests
against the *pre-fix* app code in a throwaway git worktree (this never touches your main checkout):

```bash
git worktree add /tmp/ww-vuln task2-vulnerable          # vulnerable app in a temp dir
cp tests/test_access_control.py /tmp/ww-vuln/tests/     # bring in today's tests
cd /tmp/ww-vuln && python -m pytest tests/test_access_control.py -q   # many FAIL -> flaws present
cd - && git worktree remove --force /tmp/ww-vuln        # clean up
```

**Re-running the original exploit** (needs the app running) should report `0/11 vulnerable`:

```bash
flask --app wanderways init-db && flask --app wanderways run    # terminal 1
python exploit/exploit_idor.py                                  # terminal 2
flask --app wanderways init-db                                  # reset afterwards
```

---

## 4. Operating the app safely

- **Secret key:** set `WANDERWAYS_SECRET_KEY` to a long random value in any shared/deployed environment.
  ```bash
  export WANDERWAYS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  ```
  If unset, a fresh random key is generated per process (fine for local dev; sessions reset on restart).
  Never hard-code a key.
- **Bind address:** keep it on `127.0.0.1`. Do not add `--host 0.0.0.0` without the production hardening
  in the report (HTTPS, CSRF, cookie flags, rate limiting).
- **Reset data:** `flask --app wanderways init-db` restores the deterministic 7 users / 20 bookings.
- **Do not re-introduce:** the `/api/internal/debug` endpoint, the legacy `/api/v1/*` API, the `ww_role`
  cookie, or returning `password_hash` — these were the removed vulnerabilities.

---

## 5. Where things live

| Area | File |
|---|---|
| Authorization middleware | `wanderways/authz.py` |
| Booking & user API (uses the middleware) | `wanderways/api.py` |
| Admin API (admin-only) | `wanderways/admin.py` |
| Login / sessions | `wanderways/auth.py` |
| App factory, secret key, blueprints | `wanderways/__init__.py` |
| Access-control test suite | `tests/test_access_control.py` |
| Setup / smoke tests | `tests/test_lab_setup.py` |
| Final report | `docs/SECURITY_REPORT.md` |
| Exploitation detail (how each flaw was proven) | `docs/findings_task2.md` |

**Recommended CI gate:** run `python -m pytest` on every pull request and block merge on failure, so a
change that breaks an access-control check can never reach `main`.
