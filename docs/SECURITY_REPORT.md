# WanderWays Travel Portal — Security Assessment & Remediation Report

**Access Control Hardening · Final Report (Tasks 1–3)**

| | |
|---|---|
| Intern | Suliman — Cyber Security |
| Client | Ezitech |
| System | WanderWays Travel — internal booking prototype (Python / Flask / SQLite) |
| Scope | `http://127.0.0.1:5000` — local lab, authorised testing on own machine |
| Period | 20–23 Nov 2026 |
| Repository | https://github.com/Suliman8/wanderways-access-control-hardening |
| Status | **Remediated and verified** — 11/11 findings fixed, 42 automated tests passing |

---

## 1. Executive summary

WanderWays is a travel-booking application with three roles (Admin, Agent, Customer). A security
assessment of its API found that the application **authenticated users but did not authorise them** —
it checked *who* you were, almost never *what you were allowed to access*. As a result any logged-in
customer could read, modify, cancel, steal and delete other customers' bookings, read any account's
password hash, promote themselves to admin, and an anonymous attacker could download the entire booking
database and forge an admin session.

**11 access-control vulnerabilities** were confirmed by live exploitation: **2 Critical, 7 High,
2 Medium**. All 11 have been **remediated** by introducing a central authorization layer
(`wanderways/authz.py`) and removing the information-disclosure endpoints. An **automated access-control
test suite (28 tests)** proves every attack is now blocked, and re-running the original exploit against
the fixed application reports **0/11 vulnerable** (down from 11/11).

| Phase | Outcome |
|---|---|
| Task 1 — Enumeration | 25 endpoints mapped; 5 hidden; access matrix built |
| Task 2 — Exploitation | 11/11 findings confirmed exploitable (2 Critical, 7 High, 2 Medium) |
| Task 3 — Remediation | 11/11 fixed; 42 tests passing; exploit re-run now 0/11 |

---

## 2. Scope and methodology

- **Target:** the WanderWays Flask application and its JSON API, running locally on `127.0.0.1:5000`.
- **Approach:** black-box first (an attacker with two ordinary customer accounts and one anonymous
  session), then white-box confirmation against the source code.
- **Lifecycle:** each vulnerability was **discovered** (Task 1), **exploited** to prove real impact
  (Task 2), then **remediated and re-tested** (Task 3).
- **Standards referenced:** OWASP API Security Top 10 (2023) and CWE.
- **Authorisation & ethics:** all testing was performed by the author on their own machine against this
  training application. All personal data in the app (names, emails, passport numbers, card digits) is
  fictional seed data.

**Tooling:** Python, Flask, SQLite, Burp Suite Community, ffuf, mitmproxy, Postman, pytest, Git.

The exploitable version of the code is preserved at the git tag **`task2-vulnerable`**, so the full
before/after is reproducible:

```bash
git checkout task2-vulnerable   # the vulnerable app (Tasks 1–2)
git checkout main               # the hardened app (Task 3)
```

---

## 3. Findings overview

| ID | Severity | Vulnerability | OWASP API 2023 | Status |
|----|----------|---------------|----------------|--------|
| WW-AUTH-09 | **Critical** | Secret-key disclosure → admin **session forgery** | API2 Broken Authentication | ✅ Fixed |
| WW-PRIV-06 | **Critical** | **Privilege escalation** to admin via self PATCH | API5 BFLA / API3 | ✅ Fixed |
| WW-AUTH-08 | High | **Unauthenticated** access to all bookings | API2 / API1 | ✅ Fixed |
| WW-IDOR-01 | High | Read any user's booking (horizontal **IDOR**) | API1 BOLA | ✅ Fixed |
| WW-IDOR-02 | High | Modify / re-price / **steal** any booking | API1 / API3 | ✅ Fixed |
| WW-IDOR-05 | High | Read any account incl. **password hash** | API1 / API3 | ✅ Fixed |
| WW-BAC-07 | High | Admin **user directory** exposed to non-admins | API5 BFLA | ✅ Fixed |
| WW-BAC-10 | High | Authorisation from a **client-editable cookie** | API5 BFLA | ✅ Fixed |
| WW-BAC-04 | High | **Delete** any booking as a non-admin | API5 BFLA | ✅ Fixed |
| WW-IDOR-03 | Medium | **Cancel** any user's booking | API1 BOLA | ✅ Fixed |
| WW-MASS-11 | Medium | **Mass assignment** on booking creation | API3 Mass Assignment | ✅ Fixed |

**Root cause (single sentence):** authorization logic was missing or duplicated inconsistently per route,
with no object-level ownership checks, privileged fields accepted from the client, authorisation read
from client-controlled data, and debug/legacy endpoints left exposed.

Full exploitation evidence (HTTP logs) is in [`evidence/task2/`](evidence/task2) and the detailed
exploitation write-up in [`findings_task2.md`](findings_task2.md).

---

## 4. Remediation architecture

All fixes share one design: **authorization is centralised** in a single module,
[`wanderways/authz.py`](../wanderways/authz.py), and every protected route calls into it. This replaces
the previous per-route, easy-to-forget checks.

Two layers of control:

1. **Function-level** — *can this role use this endpoint at all?*
   `role_required(*roles)` / `admin_required` guard whole endpoints (e.g. all `/api/admin/*`).
2. **Object-level** — *may this user act on THIS specific record?*
   `can_access_booking(booking, action, user)` and `can_access_user(target_id, user)` decide ownership
   for every `/{id}` route, via the `load_booking_or_error(id, action)` helper.

Supporting hardening:

- **Field allow-lists** — user-facing writes accept only non-privileged fields; `total_price`, `status`,
  `customer_id`, `agent_id` and `role` are set by the server, never mass-assigned from the request body.
- **Safe projections** — `public_user()` never returns `password_hash`.
- **Removed attack surface** — the legacy unauthenticated `/api/v1/*` API and the `/api/internal/debug`
  endpoint were deleted.
- **No client-trusted authorisation** — the unsigned `ww_role` cookie was removed; role always comes
  from the server-side session (`g.user`).
- **Secret management** — `SECRET_KEY` is read from the `WANDERWAYS_SECRET_KEY` environment variable,
  with a random per-process fallback (no hard-coded key).

---

## 5. Findings in detail (vulnerability → fix → verification)

Each entry: what was wrong, how it was fixed, and the automated test that proves it.
`tests/test_access_control.py` holds the tests named below.

### WW-AUTH-09 — Secret-key disclosure → admin session forgery · Critical
- **Was:** `GET /api/internal/debug` returned the Flask `SECRET_KEY` to anyone; it could be used to sign
  a session cookie for user id 1 and become admin with no password.
- **Fix:** the debug endpoint was deleted; `SECRET_KEY` now comes from the environment with a random
  fallback (`wanderways/__init__.py`), so it is neither exposed nor guessable.
- **Verified by:** `test_auth09_debug_endpoint_is_removed` (endpoint → 404, no key in body).

### WW-PRIV-06 — Privilege escalation via self-service PATCH · Critical
- **Was:** `PATCH /api/users/{id}` accepted a `role` field, so a customer could set `role=admin`.
- **Fix:** `role` is only in the allow-list when the caller is an admin; a customer's `role` field is
  silently dropped. Object-level `can_access_user` also blocks editing other people's profiles.
- **Verified by:** `test_priv06_customer_cannot_make_themselves_admin`,
  `test_priv06_admin_can_change_a_role`.

### WW-AUTH-08 — Unauthenticated access to all bookings · High
- **Was:** the retired `GET /api/v1/bookings[/id]` had no authentication and dumped all PII.
- **Fix:** the legacy `/api/v1/*` blueprint was removed entirely.
- **Verified by:** `test_auth08_legacy_api_is_removed` (404 for anonymous and authenticated).

### WW-IDOR-01 — Read any user's booking · High
- **Was:** `GET /api/bookings/{id}` had no ownership check.
- **Fix:** `load_booking_or_error(id, "view")` returns 403 unless the caller owns the booking (or is the
  assigned agent / an admin).
- **Verified by:** `test_idor01_customer_cannot_read_another_users_booking` (+ positive own-read / admin).

### WW-IDOR-02 — Modify / re-price / steal any booking · High
- **Was:** `PUT /api/bookings/{id}` had no ownership check and accepted `total_price`, `status`,
  `customer_id`.
- **Fix:** ownership enforced; customer writes limited to dates/notes/destination/hotel/travellers;
  price recomputed server-side; `status` staff-only; owner never client-settable.
- **Verified by:** `test_idor02_customer_cannot_modify_another_users_booking`,
  `test_idor02_price_and_owner_are_not_client_settable_on_own_booking`.

### WW-IDOR-05 — Read any account incl. password hash · High
- **Was:** `GET /api/users/{id}` returned any user's full row, including `password_hash`.
- **Fix:** self-or-admin only (`can_access_user`), and `public_user()` projection never includes the
  hash.
- **Verified by:** `test_idor05_customer_cannot_read_another_user`,
  `test_idor05_password_hash_is_never_returned`.

### WW-BAC-07 — Admin user directory exposed to non-admins · High
- **Was:** `GET /api/admin/users` used only `login_required`.
- **Fix:** `@admin_required` (server-side session role).
- **Verified by:** `test_bac07_non_admin_cannot_list_users[ayesha|agent]`, `test_bac07_admin_can_list_users`.

### WW-BAC-10 — Authorisation from a client-editable cookie · High
- **Was:** `GET /api/admin/bookings/export` trusted the unsigned `ww_role` cookie.
- **Fix:** `@admin_required`; the `ww_role` cookie was removed from the app entirely.
- **Verified by:** `test_bac10_export_ignores_the_ww_role_cookie`, `test_bac10_admin_can_export`.

### WW-BAC-04 — Delete any booking as a non-admin · High
- **Was:** `DELETE /api/bookings/{id}` only required login.
- **Fix:** `can_access_booking(..., "delete", ...)` returns true only for admins; non-admins get 403.
- **Verified by:** `test_bac04_customer_cannot_delete_a_booking`, `..._agent_...`, `..._admin_can_delete...`.

### WW-IDOR-03 — Cancel any user's booking · Medium
- **Was:** `POST /api/bookings/{id}/cancel` had no ownership check.
- **Fix:** `load_booking_or_error(id, "cancel")` — owner, assigned agent or admin only.
- **Verified by:** `test_idor03_customer_cannot_cancel_another_users_booking` (+ positive own-cancel).

### WW-MASS-11 — Mass assignment on booking creation · Medium
- **Was:** `POST /api/bookings` honoured client `total_price`, `customer_id`, `status`.
- **Fix:** owner = caller, price = server-computed, status = `pending`; privileged fields ignored.
- **Verified by:** `test_mass11_create_ignores_privileged_fields`.

---

## 6. Verification

Two independent checks confirm the remediation:

**1. Automated access-control test suite** — `tests/test_access_control.py`, 28 tests, one group per
finding (attack blocked + legitimate action still works), plus the lab-setup suite:

```
$ python -m pytest -q
42 passed
```
Full output: [`evidence/task3/test_results.txt`](evidence/task3/test_results.txt).

**2. Re-running the original Task 2 exploit** against the hardened app:

```
$ python exploit/exploit_idor.py
0/11 confirmed VULNERABLE
```
Before/after logs: [`evidence/task2/findings_summary.txt`](evidence/task2/findings_summary.txt) (11/11)
→ [`evidence/task3/after_fix/findings_summary.txt`](evidence/task3/after_fix/findings_summary.txt) (0/11).

| Check | Before (task2-vulnerable) | After (main) |
|---|---|---|
| Exploit script result | 11/11 vulnerable | **0/11 vulnerable** |
| Access-control tests | (would fail) | **28/28 passing** |
| Total test suite | — | **42/42 passing** |

---

## 7. Residual risk and recommendations

The access-control objective (data isolation between users) is met. For a move beyond a training lab,
the following are recommended next steps (out of scope for this engagement):

1. **Return 404 instead of 403** for objects the caller may not access, to avoid confirming that a
   record exists (resource-enumeration hardening). Current behaviour returns 403, which is clear for
   teaching but slightly more revealing.
2. **Rate limiting and audit logging** on authentication and on `/{id}` access, to detect ID-walking.
3. **CSRF protection** and `Secure` / `HttpOnly` cookie flags once served over HTTPS.
4. **Password-reset / account-lockout** flows and stronger session lifecycle management.
5. **A CI gate** that runs `tests/test_access_control.py` on every pull request, so a future change that
   re-introduces an IDOR fails the build (see the handover document).

---

## 8. Conclusion

WanderWays moved from **11 exploitable access-control flaws** to **none**, verified by an automated
test suite and by re-running the original exploit. Authorization is now enforced consistently in one
place, making the controls easy to review and hard to bypass. Maintenance guidance for future developers
is in [`HANDOVER.md`](HANDOVER.md).

---

### Appendix — document map

| Deliverable | File |
|---|---|
| Vulnerability Assessment Report (exploitation detail) | `docs/findings_task2.md` |
| This final lifecycle report | `docs/SECURITY_REPORT.md` |
| Remediation Patch Set | git range `task2-vulnerable..main`; `wanderways/authz.py` + route changes |
| Automated Access Control Test Suite | `tests/test_access_control.py` (28 tests) |
| Security Handover Document | `docs/HANDOVER.md` |
| Endpoint map (Task 1) | `docs/api_endpoints.txt` |
| Evidence | `docs/evidence/task1_*`, `docs/evidence/task2/`, `docs/evidence/task3/` |
