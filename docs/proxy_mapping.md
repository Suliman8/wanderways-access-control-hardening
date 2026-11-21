# Mapping WanderWays traffic with a proxy (Burp Suite)

Task 1, step 3 says: *"Use a proxy tool to map all traffic and identify hidden API endpoints."*

## What a proxy does

Normally your browser talks straight to the website. A **proxy** such as Burp Suite sits **in the
middle** and writes down every request that passes through it:

```
  browser / script  ──────►  Burp Suite  ──────►  WanderWays app
                             127.0.0.1:8081       127.0.0.1:5000
                             (records every request)
```

When you click around the site, Burp builds a list of every URL the site uses: `/api/bookings`,
`/api/admin/users` and so on. That list is the **map of the API**.

There is one catch, and it is the main lesson of Task 1. Burp only records URLs that the website
**actually calls**. Hidden endpoints (no page uses them) never pass through Burp, so they must be found
with extra techniques ([part C](#c-finding-the-hidden-endpoints)).

---

## A. Burp Suite: do it yourself (about 10 minutes)

### Step 1: Start the app

Terminal 1:

```bash
cd ~/Desktop/Eztech/wanderways-access-control-hardening
source .venv/bin/activate
flask --app wanderways init-db
flask --app wanderways run
```

Leave this terminal open. The app is now at http://127.0.0.1:5000.

### Step 2: Open Burp

Open **Burp Suite Community** from the menu (or type `burpsuite` in a terminal).
Click **Temporary project** → **Next** → **Use Burp defaults** → **Start Burp**.

### Step 3: Change Burp's port from 8080 to 8081

Burp normally listens on port 8080, but on this computer another program already uses 8080. If Burp
shows *"Failed to start proxy service on 127.0.0.1:8080"*, that is the reason.

1. Click the **Proxy** tab, then the **Proxy settings** button (top right).
2. Under **Proxy listeners**, click the `127.0.0.1:8080` row → **Edit**.
3. Change **Bind to port** to `8081` → **OK**.
4. Make sure the **Running** box on that row is ticked. Close the settings window.

### Step 4: Turn "Intercept" off

**Proxy** tab → **Intercept**. The button must show **Intercept off**.
(When intercept is on, every request stops and waits for you to press *Forward*. We only want to record.)

### Step 5: Send traffic through Burp

**Easiest: one command.** Open terminal 2:

```bash
cd ~/Desktop/Eztech/wanderways-access-control-hardening
source .venv/bin/activate
python scripts/generate_traffic.py --proxy http://127.0.0.1:8081
```

The script acts like a person: it logs in as the customer, the agent and the admin and opens every
page, all through Burp. It only reads data, so nothing needs resetting afterwards.

**Or by hand:** **Proxy** → **Intercept** → **Open browser**. In that browser go to
http://127.0.0.1:5000 and:

| Log in as | Then click |
|---|---|
| `ayesha` / `Customer@2026` | Bookings → open a booking → New booking → Profile → Log out |
| `sara.agent` / `Agent@2026` | Bookings → open a booking → Profile → Log out |
| `admin` / `Admin@2026` | Bookings → open a booking → Profile → Admin → Export bookings → Log out |

### Step 6: Look at the map

Click the **Target** tab → **Site map** → click the small arrow next to `http://127.0.0.1:5000`.
Open the folders (`api`, `admin`, `bookings`, …). You now see every URL the site used, with its
method (GET, POST, …).
The **Proxy → HTTP history** tab shows the same requests as a list, in the order they happened.

### Step 7: Save a screenshot as evidence

With the folders open, take a screenshot (PrtSc key, or the Kali *Screenshot* app). Save it as
`docs/evidence/screenshots/burp_sitemap.png`, then in terminal 2:

```bash
git add docs/evidence/screenshots/burp_sitemap.png
git commit -m "Add Burp Suite site map screenshot"
git push
```

### Optional: two Burp tricks used in the enumeration

* **Find hidden clues in the JavaScript:** in the Site map click `app.js` → **Response** tab →
  search for `/api`. You will find a developer comment mentioning `/api/v1/bookings`, a hidden endpoint.
* **See which methods a URL accepts:** right-click a request → **Send to Repeater**. In Repeater
  change the first word (`GET`) to `OPTIONS` and click **Send**. The `Allow` header in the answer
  lists the methods. This is how `DELETE /api/bookings/{id}` was found.

---

## B. How the saved capture in this repo was made (mitmproxy)

Burp is a desktop window that has to be clicked by hand. The capture saved in `docs/evidence/proxy/`
was made with **mitmproxy**, a proxy that runs in the terminal and does the same job (it sits in the
middle and records). The same user journeys went through it:

```bash
# terminal 1 - proxy on 127.0.0.1:8081, saving everything it sees
mitmdump --listen-host 127.0.0.1 -p 8081 \
  -w docs/evidence/proxy/wanderways_capture.mitm \
  --set hardump=docs/evidence/proxy/wanderways_capture.har

# terminal 2 - every role's journey through the proxy (76 requests, including POST/PUT/PATCH)
python scripts/generate_traffic.py --proxy http://127.0.0.1:8081 --with-writes \
  > docs/evidence/proxy/traffic_generator_output.txt

# stop mitmdump with Ctrl+C, then turn the capture into readable files
python recon/har_sitemap.py docs/evidence/proxy/wanderways_capture.har --out docs/evidence/proxy
flask --app wanderways init-db     # --with-writes added a test booking; this removes it
```

| File | What it is |
|---|---|
| `proxy_sitemap.txt` | the URL tree, like Burp's *Site map* |
| `proxy_history.txt` | every request in order, like Burp's *HTTP history* |
| `wanderways_capture.har` | full requests and responses (open in Chrome/Firefox DevTools → Network → Import) |
| `wanderways_capture.mitm` | the same capture for mitmproxy (`mitmweb -r wanderways_capture.mitm`) |

---

## C. Finding the hidden endpoints

```bash
python recon/enumerate_endpoints.py --routes docs/evidence/flask_routes.txt --out docs/evidence
```

This script starts from the same clues Burp shows (robots.txt, links, JavaScript). It then guesses
common names under every folder found so far (a wordlist, like ffuf), tries `<list>/1` to find
single-item URLs, and asks every URL for its allowed methods with `OPTIONS`. It only reads, never
changes data, and refuses any target that is not your own computer.

## What the proxy saw vs. what exists

| | Paths |
|---|---|
| Seen in proxy traffic | 18 |
| Found only by the extra techniques | 7 (`/health`, `/robots.txt`, `/logout`, `/api/auth/me`, `/api/internal/debug`, `/api/v1/bookings`, `/api/v1/bookings/{id}`) |
| **Total (= `flask routes`)** | **25** |

Using only the proxy would have missed 28% of the endpoints, including the two most serious ones
(the v1 API that needs no login, and the debug page that leaks the secret key).
Full results: [`api_endpoints.txt`](api_endpoints.txt).
