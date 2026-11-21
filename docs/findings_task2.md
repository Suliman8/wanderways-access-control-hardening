# WanderWays Travel Portal — Vulnerability Assessment Report (Task 2)

**Exploiting IDOR and Broken Access Control**

| | |
|---|---|
| Intern | Suliman — Cyber Security |
| Client | Ezitech |
| Target | `http://127.0.0.1:5000` (local lab, authorised testing on own machine) |
| Date | 22 Nov 2026 |
| Method | Black-box API testing with two real accounts, plus one anonymous attacker |
| Attacker | `ayesha` — customer, user id 4 (owns bookings 1, 5, 9, 13, 17) |
| Victim | `omar` — customer, user id 5 (owns bookings 2, 6, 10, 14, 18) |

> ⚠️ This is an **intentionally vulnerable training app**. Every weakness below is real in this lab and
> was confirmed by sending live HTTP requests. Remediation is **Task 3**; nothing is fixed here.

## How this was tested

Task 1 mapped the API and listed the suspicious endpoints. Task 2 **confirms** each one by actually
performing the unauthorised action and recording the server's response.

- **Two sessions / two browser profiles** (the brief's step 1): the attacker `ayesha` and the victim
  `omar` are separate accounts. `ayesha` only ever uses her own login, then reaches into `omar`'s data.
- **ID manipulation** (steps 2–3): capture a normal request, change the `{id}` in the URL (or a field
  in the body) to a value the attacker does not own, and replay it.
- **Logging** (step 4): every request and response is saved to
  [`docs/evidence/task2/exploit_log.txt`](evidence/task2/exploit_log.txt).

Everything is reproducible with one script:

```bash
flask --app wanderways init-db      # deterministic data
flask --app wanderways run          # terminal 2
python exploit/exploit_idor.py      # terminal 3  -> writes docs/evidence/task2/
```

The script is pure black-box HTTP (it never touches the database directly), so it is a faithful
attacker's-eye proof of concept. Burp Suite reproduction of two findings by hand is in
[`task2_burp_walkthrough.md`](task2_burp_walkthrough.md).

## Result: 11 / 11 test cases confirmed vulnerable

| # | ID | Severity | Flaw | Endpoint | OWASP API Top 10 (2023) |
|---|----|----------|------|----------|-------------------------|
| 1 | WW-AUTH-09 | **Critical** | Secret-key disclosure → admin **session forgery** | `GET /api/internal/debug` | API2 Broken Authentication |
| 2 | WW-PRIV-06 | **Critical** | **Privilege escalation** to admin via self PATCH | `PATCH /api/users/{id}` | API5 BFLA / API3 Mass Assignment |
| 3 | WW-AUTH-08 | High | **Unauthenticated** dump of all bookings | `GET /api/v1/bookings` | API2 / API1 BOLA |
| 4 | WW-IDOR-01 | High | Read any user's booking (horizontal **IDOR**) | `GET /api/bookings/{id}` | API1 BOLA |
| 5 | WW-IDOR-02 | High | Modify / re-price / **steal** any booking | `PUT /api/bookings/{id}` | API1 BOLA / API3 |
| 6 | WW-IDOR-05 | High | Read any account incl. **password hash** | `GET /api/users/{id}` | API1 BOLA / API3 |
| 7 | WW-BAC-07 | High | Admin **user directory** exposed to non-admins | `GET /api/admin/users` | API5 BFLA |
| 8 | WW-BAC-10 | High | Authorisation from a **client-editable cookie** | `GET /api/admin/bookings/export` | API5 BFLA |
| 9 | WW-BAC-04 | High | **Delete** any booking as a non-admin | `DELETE /api/bookings/{id}` | API5 BFLA |
| 10 | WW-IDOR-03 | Medium | **Cancel** any user's booking | `POST /api/bookings/{id}/cancel` | API1 BOLA |
| 11 | WW-MASS-11 | Medium | **Mass assignment** on booking creation | `POST /api/bookings` | API3 Mass Assignment |

**Root cause (one sentence):** the API authenticates *who you are* but almost never checks *what you are
allowed to touch* — there is no per-object ownership check and the admin role is enforced on only some
routes. Fixes belong in Task 3.

---

## Findings

Each finding lists the request the attacker sent and the server's answer. Full exchanges (with the `>`
request / `<` response lines) are in `docs/evidence/task2/exploit_log.txt`.

### WW-AUTH-09 — Secret-key disclosure enabling admin session forgery · Critical
*`GET /api/internal/debug` · CWE-200 / CWE-287 · OWASP API2:2023*

**Intended:** the debug endpoint should not exist in production and must never reveal secrets.
**Actual:** it answers with no authentication and leaks the Flask signing key.

```
GET /api/internal/debug            ->  200  {"secret_key": "wanderways-dev-secret", ...}
```

With that key the attacker signs their own Flask session cookie for `user_id = 1` (admin) and uses it:

```
GET /api/admin/stats   Cookie: session=<forged, signed with leaked key>   ->  200 OK
```

No password is ever used. The cookie is forged offline using the standard Flask/itsdangerous format.

**Impact:** complete authentication bypass. The attacker can mint a valid session for **any** user,
including admin, and do everything that user can. This is the most severe issue found — it turns every
"admin only" control into "anyone only".

---

### WW-PRIV-06 — Privilege escalation to admin via self-service PATCH · Critical
*`PATCH /api/users/{id}` · CWE-269 / CWE-915 · OWASP API5 / API3*

**Intended:** a user may edit their own name/email/phone; only an admin may change a `role`.
**Actual:** the profile endpoint accepts a `role` field from anyone.

```
# before: as a customer, admin stats is correctly blocked
GET   /api/admin/stats            ->  403

# attack: promote myself
PATCH /api/users/4  {"role":"admin"}   ->  200  {"role":"admin"}

# proof: same account now passes the admin check
GET   /api/admin/stats            ->  200
```

**Impact:** any customer becomes an admin in a single request, with no re-authentication, then gains
every admin capability (user directory, stats, exports). Account-takeover-grade.

---

### WW-AUTH-08 — Unauthenticated access to all bookings (legacy v1 API) · High
*`GET /api/v1/bookings`, `GET /api/v1/bookings/{id}` · CWE-306 · OWASP API2 / API1*

**Intended:** booking data requires a login.
**Actual:** the retired mobile endpoint has no auth at all.

```
GET /api/v1/bookings       (no cookie)  ->  200  {"count": 20, "bookings": [... all PII ...]}
GET /api/v1/bookings/2     (no cookie)  ->  200  (Omar's booking)
```

**Impact:** a completely unauthenticated attacker exfiltrates every booking — names, emails, passport
numbers and card last-4. A mass data breach reachable by anyone who can hit the URL.

---

### WW-IDOR-01 — Read any user's booking (horizontal IDOR) · High
*`GET /api/bookings/{id}` · CWE-639 · OWASP API1:2023 (BOLA)*

**Intended:** a customer sees only their own bookings.
**Actual:** no ownership check — the ID alone decides.

```
# attacker's own booking (legitimate baseline)
GET /api/bookings/1   (ayesha)  ->  200  "customer_name": "Ayesha Khan"

# attack: someone else's booking
GET /api/bookings/2   (ayesha)  ->  200  "customer_name": "Omar Farooq",
                                          "passport_no": "ZX6983360", "payment_last4": "6166"
```

**Impact:** by walking sequential IDs (1, 2, 3 …) any logged-in user reads every customer's booking and
sensitive PII. This is the headline IDOR the brief asks to prove.

---

### WW-IDOR-02 — Modify / re-price / steal any booking · High
*`PUT /api/bookings/{id}` · CWE-639 / CWE-915 · OWASP API1 / API3*

**Intended:** a customer may edit dates/notes on their own booking; price, status and owner are not
theirs to set.
**Actual:** no ownership check and privileged fields are client-writable.

```
PUT /api/bookings/6  (ayesha)  {"notes":"TAMPERED by ayesha","total_price":0,"status":"confirmed"}
                               ->  200  (Omar's booking, now $0 and confirmed)
PUT /api/bookings/6  (ayesha)  {"customer_id":4}   ->  200  (ownership transferred to the attacker)
```

**Impact:** an attacker rewrites anyone's trip, zeroes the price (payment fraud), confirms unpaid
bookings, or reassigns ownership to steal a booking outright.

---

### WW-IDOR-05 — Read any user account incl. password hash · High
*`GET /api/users/{id}` · CWE-639 / CWE-200 · OWASP API1 / API3*

```
GET /api/users/1  (ayesha)  ->  200  {"username":"admin","email":"...","password_hash":"scrypt:..."}
```

**Intended:** a user reads only their own profile; a hash is never returned.
**Actual:** any user reads any account, and the response includes the password hash.

**Impact:** the full account directory plus password hashes leak to any user. Hashes enable offline
cracking; emails/phones enable phishing. Feeds directly into WW-AUTH-09 (forging that user's session).

---

### WW-BAC-07 — Admin user directory exposed to non-admins · High
*`GET /api/admin/users` · CWE-862 · OWASP API5:2023 (BFLA)*

```
GET /api/admin/users  (ayesha, customer)  ->  200  {"count": 7, "users": [... all accounts ...]}
GET /api/admin/stats  (ayesha, customer)  ->  403   (this route IS protected)
```

**Intended:** admin only.
**Actual:** the role check was omitted on this route (but present on `/api/admin/stats`, proving the
guard was simply forgotten here — inconsistent enforcement).

**Impact:** every username, email, phone and role leaks to any logged-in user.

---

### WW-BAC-10 — Authorisation from a client-editable cookie (CSV export) · High
*`GET /api/admin/bookings/export` · CWE-639 / CWE-602 · OWASP API5*

Login sets an **unsigned** `ww_role` cookie that the export route trusts.

```
GET /api/admin/bookings/export   Cookie: ww_role=customer   ->  403
GET /api/admin/bookings/export   Cookie: ww_role=admin      ->  200  (CSV of all bookings)
```

The attacker simply edits the cookie value. Saved result:
[`evidence/task2/leaked_bookings_export.csv`](evidence/task2/leaked_bookings_export.csv).

**Impact:** anyone downloads the entire booking database (names, emails, passports, card last-4) by
changing one cookie value in their browser. Authorisation must never come from client-controlled data.

---

### WW-BAC-04 — Delete any booking as a non-admin · High
*`DELETE /api/bookings/{id}` · CWE-862 · OWASP API5:2023 (BFLA)*

```
DELETE /api/bookings/14  (ayesha, customer)  ->  200  "deleted"
GET    /api/bookings/14  (ayesha)            ->  404  (gone)
```

**Intended:** admin only (the UI has no delete button).
**Actual:** any logged-in user can permanently delete any booking.

**Impact:** destructive, irreversible action available to every user — data loss / denial of service.

---

### WW-IDOR-03 — Cancel any user's booking · Medium
*`POST /api/bookings/{id}/cancel` · CWE-639 · OWASP API1 (BOLA)*

```
POST /api/bookings/10/cancel  (ayesha)  ->  200  "status": "cancelled"   (Omar's booking)
```

**Impact:** any user cancels other customers' trips — sabotage, lost revenue, customer harm.

---

### WW-MASS-11 — Mass assignment on booking creation · Medium
*`POST /api/bookings` · CWE-915 · OWASP API3:2023 (Mass Assignment)*

```
POST /api/bookings  (ayesha)  {"destination":"Dubai, UAE", ..., "total_price":0,
                               "customer_id":5, "status":"confirmed"}   ->  201
```

**Intended:** the server sets price, owner and status.
**Actual:** it honours them from the request body.

**Impact:** attackers create confirmed, zero-price bookings, or plant bookings under another customer's
account — pricing and ownership bypass.

---

## What Task 3 must fix (preview)

The whole class of bugs comes from two missing checks. Task 3 will add:

1. **Object-level authorisation** — every `/{id}` route must verify the logged-in user **owns** (or, for
   agents/admins, is allowed to touch) that specific object, not just that they are logged in.
2. **Function-level authorisation** — a reusable `@admin_required` guard, derived from the **server-side
   session**, on every admin route (the pattern already used correctly on `/api/admin/stats`).
3. **Field allow-lists** — never accept `role`, `total_price`, `status`, `customer_id` from the client on
   user-facing routes (fix mass assignment).
4. **Remove the leaks** — delete `/api/internal/debug` and the legacy `/api/v1/*` API, stop returning
   `password_hash`, load `SECRET_KEY` from the environment, and stop trusting the `ww_role` cookie for
   authorisation.

An automated access-control test suite (also Task 3) will re-run every finding above and assert it now
returns **403/401** instead of 200.
