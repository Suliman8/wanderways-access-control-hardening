# Mapping WanderWays traffic with an intercepting proxy

Task 1, step 3: *"Use a proxy tool to map all traffic and identify hidden API endpoints."*

The proxy shows what the application **does** while people use it. Hidden endpoints never show up in
that traffic. They are found afterwards from clues in the proxy (robots.txt, JavaScript, `Allow`
headers) and by active discovery. This page covers both parts.

---

## A. Burp Suite Community

### 1. Start the lab

```bash
source .venv/bin/activate
flask --app wanderways init-db      # fresh data
flask --app wanderways run          # http://127.0.0.1:5000
```

### 2. Start Burp and set the listener

1. Open Burp Suite Community → **Temporary project** → **Use Burp defaults** → **Start Burp**.
2. **Proxy → Proxy settings → Proxy listeners.** The default is `127.0.0.1:8080`.
   On the test machine port 8080 was already used by another service, so the listener was edited to
   **`127.0.0.1:8081`**. Use any free port and use the same port below.
3. **Proxy → Intercept**: make sure **Intercept is off**. Otherwise every request waits for you.

### 3. Set the scope

**Target → Scope settings → Include in scope → Add** → `http://127.0.0.1:5000`.
In **Target → Site map**, click the filter bar and tick **Show only in-scope items**.

### 4. Generate traffic as every role

Option 1, by hand: **Proxy → Intercept → Open browser** (Burp's built-in Chromium already sends
traffic to 127.0.0.1 through Burp). Then, for each account in the README:

| Account | Click through |
|---|---|
| not logged in | `/`, the login page, one wrong password |
| `ayesha` (customer) | Bookings → open a booking → *Save changes* → *Cancel booking* → New booking → submit → Profile → *Save profile* → Log out |
| `sara.agent` (agent) | Bookings → open a booking → Profile → Log out |
| `admin` | Bookings → open a booking → Profile → Admin → *Export bookings (CSV)* → Log out |

Option 2, scripted: replay the same journeys through Burp:

```bash
python scripts/generate_traffic.py --proxy http://127.0.0.1:8081 --with-writes
flask --app wanderways init-db      # remove the test booking afterwards
```

### 5. Read the map

* **Target → Site map** → expand `http://127.0.0.1:5000`. This gives the endpoint tree the UI uses.
* **Proxy → HTTP history** shows every request with method, status and length. Sort by URL to group them.
* Click `GET /static/js/app.js` → **Response** and search for `/api`. Every `fetch()` path is there,
  plus a developer comment: *"the old mobile app still reads /api/v1/bookings"*. That is a hidden endpoint.
* Open `GET /robots.txt`: `Disallow: /admin` and `Disallow: /api/internal/`. Two more leads.

### 6. Confirm hidden endpoints and methods

* **Repeater:** right-click any request → *Send to Repeater*. Change the path to `/api/v1/bookings`,
  then to `/api/internal/` + a guess. Change the method to `OPTIONS`: the `Allow` response header lists
  the methods the server accepts. This is how `DELETE /api/bookings/{id}` was found.
* **Intruder** works for wordlist fuzzing, but Burp Community slows it down on purpose. For the full
  wordlist use ffuf or the project script instead (part C).

### 7. Save evidence

* Take a screenshot of the expanded **Site map** and save it as `docs/evidence/screenshots/burp_sitemap.png`.
* Optional: in **HTTP history** select all rows → right-click → **Save items** (XML file).

---

## B. mitmproxy (how the committed capture was made)

The capture in `docs/evidence/proxy/` was recorded headless with mitmproxy 11.1.2, which is a
command-line intercepting proxy. It covers the same journeys as part A, so the result does not depend
on screenshots:

```bash
# terminal 1 - proxy on 127.0.0.1:8081, save flows + a HAR file
mitmdump --listen-host 127.0.0.1 -p 8081 \
  -w docs/evidence/proxy/wanderways_capture.mitm \
  --set hardump=docs/evidence/proxy/wanderways_capture.har

# terminal 2 - every role's journey through the proxy (76 requests)
python scripts/generate_traffic.py --proxy http://127.0.0.1:8081 --with-writes \
  > docs/evidence/proxy/traffic_generator_output.txt

# stop mitmdump with Ctrl+C (writes the HAR), then build the readable views
python recon/har_sitemap.py docs/evidence/proxy/wanderways_capture.har --out docs/evidence/proxy
flask --app wanderways init-db
```

| File | What it is |
|---|---|
| `proxy_sitemap.txt` | site-map tree with methods, status codes and hit counts (like Burp's Site map) |
| `proxy_history.txt` | every request in order (like Burp's HTTP history) |
| `wanderways_capture.har` | full requests and responses. Open in Chrome/Firefox DevTools → Network → Import |
| `wanderways_capture.mitm` | the same flows for mitmproxy: `mitmweb -r wanderways_capture.mitm` |

---

## C. Active discovery (after the proxy)

```bash
python recon/enumerate_endpoints.py --routes docs/evidence/flask_routes.txt --out docs/evidence
```

The script repeats the clues from the proxy automatically (robots.txt, crawl as every role,
JavaScript strings and comments). It then fuzzes the wordlist under every folder found so far, probes
`<collection>/1` for item routes, and reads the `Allow` header of every path. Finally it sends a GET as
every role to build an access matrix. Only GET, HEAD and OPTIONS are used.

## What the proxy saw vs. what exists

| | Paths |
|---|---|
| Seen in proxy traffic | 18 |
| Found only by active discovery | 7 (`/health`, `/robots.txt`, `/logout`, `/api/auth/me`, `/api/internal/debug`, `/api/v1/bookings`, `/api/v1/bookings/{id}`) |
| **Total (= `flask routes`)** | **25** |

Passive proxying alone would have missed 28% of the attack surface, including the two most serious
leads (the unauthenticated v1 API and the debug endpoint). Full results: [`api_endpoints.txt`](api_endpoints.txt).
