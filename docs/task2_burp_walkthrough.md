# Task 2 — reproducing the IDOR by hand in Burp Suite

The script `exploit/exploit_idor.py` already proves all 11 findings and saves the log. This page shows
how to reproduce the **headline IDOR by hand in Burp**, so you have a screenshot for the submission (the
brief lists Burp Suite as a tool). It takes about 10 minutes and uses Burp Repeater — the classic way to
"change the ID and resend".

## Setup

```bash
flask --app wanderways init-db      # fresh data
flask --app wanderways run          # terminal 1  -> http://127.0.0.1:5000
```

Start Burp (Temporary project → Use Burp defaults). Set the proxy listener to **127.0.0.1:8081** and
**Intercept off** — same as Task 1 (`docs/proxy_mapping.md`), because port 8080 is used on this machine.

Use Burp's built-in browser: **Proxy → Intercept → Open browser**.

## Finding WW-IDOR-01 — read another user's booking

1. In Burp's browser, go to `http://127.0.0.1:5000` and log in as the **attacker**:
   `ayesha` / `Customer@2026`.
2. Open her booking **WW-26-1001** (the first row). The page calls `GET /api/bookings/1`.
3. In Burp go to **Proxy → HTTP history**, find `GET /api/bookings/1`, right-click it →
   **Send to Repeater**.
4. Open the **Repeater** tab. You see the request with `ayesha`'s session cookie. In the request line,
   change the path from `/api/bookings/1` to **`/api/bookings/2`** (booking #2 belongs to **omar**, a
   different customer).
5. Click **Send**. In the response pane you get **`200 OK`** and omar's booking:
   `"customer_name": "Omar Farooq"`, plus `"passport_no"` and `"payment_last4"` that are not yours.

   > This is the proof: ayesha is logged in as herself, never as omar, yet the server hands over omar's
   > booking and passport number. The server failed to check ownership.

6. **Screenshot** the Repeater tab showing the modified request (`/api/bookings/2`) on the left and the
   `200 OK` response with `"customer_name": "Omar Farooq"` on the right. Save it as
   `docs/evidence/task2/screenshots/burp_idor_booking.png`.

Optional contrast: change the path to `/api/bookings/999` → `404`, and send the same `/api/bookings/2`
with **no cookie** (delete the `Cookie:` header) → `401`. This shows the data needs *a* login but not the
*right* login — a textbook IDOR.

## Finding WW-PRIV-06 — make yourself admin (optional second screenshot)

1. Still as `ayesha`, find any request in HTTP history and send it to Repeater.
2. Change it to:
   ```
   PATCH /api/users/4 HTTP/1.1
   Host: 127.0.0.1:5000
   Content-Type: application/json
   Cookie: <ayesha's session cookie, left as-is>

   {"role":"admin"}
   ```
3. **Send** → `200 OK`, response shows `"role": "admin"`.
4. Change a second Repeater tab to `GET /api/admin/stats` with the same cookie → it now returns
   `200 OK` (before the PATCH it returned `403`). You escalated a customer to admin.
5. Screenshot and save as `docs/evidence/task2/screenshots/burp_privesc.png`.
6. Reset the lab afterwards: `flask --app wanderways init-db`.

## After taking screenshots

```bash
git add docs/evidence/task2/screenshots/
git commit -m "Add Burp Repeater screenshots for Task 2 IDOR and privilege escalation"
git push
```

If you prefer **Postman** (also named in the brief): import
`exploit/wanderways_idor.postman_collection.json`, run **Login as ayesha**, then **IDOR – read Omar's
booking**. The same `200` + `Omar Farooq` response is the proof.
