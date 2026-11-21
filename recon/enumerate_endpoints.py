#!/usr/bin/env python3
"""Black-box endpoint enumeration for the WanderWays lab.

Discovery (no source code needed):
  1. robots.txt        - paths the developers asked crawlers to skip
  2. crawl             - HTML links, forms and scripts, once per identity
                         (anonymous, customer, agent, admin)
  3. JavaScript        - API paths in the code (fetch calls, template strings)
                         and, separately, paths mentioned only in comments
  4. wordlist fuzzing  - common names under every parent path found so far,
                         repeated until nothing new turns up
  5. ID probing        - "<collection>/1" to find item routes
Every candidate is confirmed with OPTIONS (the Allow header gives the HTTP
methods), then sent a GET as each identity to build a baseline access matrix.

Safe by design: only GET, HEAD and OPTIONS are sent, so no data changes.
Logout URLs are recorded but never requested with GET.

Usage:
    python recon/enumerate_endpoints.py
    python recon/enumerate_endpoints.py --routes docs/evidence/flask_routes.txt --out docs/evidence
    python recon/enumerate_endpoints.py --proxy http://127.0.0.1:8081   # send through Burp
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

ACCOUNTS = {
    "customer": ("ayesha", "Customer@2026"),
    "agent": ("sara.agent", "Agent@2026"),
    "admin": ("admin", "Admin@2026"),
}
IDENTITIES = ("anonymous", "customer", "agent", "admin")
EXISTS = {200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 405}
REDIRECTS = {301, 302, 303, 307, 308}
NEVER_GET = ("logout",)          # a GET here would end our session
ID = "{id}"
PROBE_ID = "1"
HIDDEN_SOURCES = {"robots", "wordlist", "id-probe", "js-comment"}

QUOTED_PATH = re.compile(r"""^/[A-Za-z0-9_\-./${}]*$""")
API_IN_TEXT = re.compile(r"(/api/[A-Za-z0-9_\-/.${}]*[A-Za-z0-9_}])")
TEMPLATE_VAR = re.compile(r"\$\{[^}]*\}")


# --------------------------------------------------------------------------- helpers

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link") and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self.forms.append((a.get("action") or "", (a.get("method") or "GET").upper()))


def split_js(source):
    """Return (string literals, comment text) from JavaScript using a small scanner."""
    strings, comments, i, n = [], [], 0, len(source)
    while i < n:
        c = source[i]
        if c in "\"'`":
            j, buf = i + 1, []
            while j < n and source[j] != c:
                if source[j] == "\\":
                    buf.append(source[j:j + 2])
                    j += 2
                    continue
                buf.append(source[j])
                j += 1
            strings.append("".join(buf))
            i = j + 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end == -1 else end
            comments.append(source[i:end])
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            comments.append(source[i:end])
            i = end
        else:
            i += 1
    return strings, comments


def normalize(path):
    """'/api/bookings/7?x=1' -> '/api/bookings/{id}', '/bookings/${b.id}' -> '/bookings/{id}'."""
    path = urlparse(TEMPLATE_VAR.sub(ID, path)).path
    path = "/".join(ID if seg.isdigit() else seg for seg in path.split("/"))
    return path.rstrip("/") or "/"


def concrete(template):
    return template.replace(ID, PROBE_ID)


def parents(template):
    segs = template.strip("/").split("/")
    return {"/" + "/".join(segs[:i]) for i in range(1, len(segs))} | {""}


def kind(path):
    if path.startswith("/static/"):
        return "static"
    return "api" if path.startswith("/api/") else "page"


def same_origin(base, url):
    target = urlparse(urljoin(base + "/", url))
    origin = urlparse(base)
    return target.netloc == origin.netloc and target.scheme == origin.scheme, target.path


# --------------------------------------------------------------------------- scanner

class Enumerator:
    def __init__(self, base, proxy, words, verbose):
        self.base = base.rstrip("/")
        self.proxy = proxy
        self.words = words
        self.verbose = verbose
        self.requests = 0
        self.candidates = {}   # template -> set(sources)
        self.endpoints = {}    # template -> {"sources", "allow"}
        self.not_found = set()
        self.robots = []
        self.js_files = set()
        self.sessions = {}

    # -- http
    def session(self):
        s = requests.Session()
        s.trust_env = False
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.headers["User-Agent"] = "wanderways-recon/1.0 (authorised lab test)"
        return s

    def send(self, s, method, path, **kw):
        kw.setdefault("timeout", 10)
        kw.setdefault("allow_redirects", False)
        self.requests += 1
        r = s.request(method, self.base + path, **kw)
        if self.verbose:
            print(f"    {method:<7} {path:<40} {r.status_code}")
        return r

    def note(self, path, source):
        template = normalize(path)
        if not template.startswith("//"):
            self.candidates.setdefault(template, set()).add(source)
        return template

    # -- phase 1
    def read_robots(self):
        r = self.send(self.sessions["anonymous"], "GET", "/robots.txt")
        if r.status_code != 200:
            return
        self.note("/robots.txt", "well-known")
        for line in r.text.splitlines():
            field, _, value = line.partition(":")
            if field.strip().lower() in ("allow", "disallow") and value.strip():
                self.robots.append(value.strip())
                self.note(value.strip(), "robots")

    # -- phase 2
    def login_all(self):
        """Log in through the HTML form found on /login, like a user would."""
        for role, (username, password) in ACCOUNTS.items():
            s = self.session()
            r = self.send(s, "POST", "/login", data={"username": username, "password": password})
            if r.status_code not in REDIRECTS:
                sys.exit(f"login failed for {role} ({username}): HTTP {r.status_code}")
            self.sessions[role] = s

    def crawl(self, identity, limit=80):
        s = self.sessions[identity]
        queue, seen = ["/"], set()
        while queue and len(seen) < limit:
            path = queue.pop(0)
            if path in seen or any(w in path for w in NEVER_GET):
                continue
            seen.add(path)
            r = self.send(s, "GET", path)
            if r.status_code == 404:
                continue
            self.note(path, "crawl")
            if r.status_code in REDIRECTS and "Location" in r.headers:
                ok, target = same_origin(self.base, r.headers["Location"])
                if ok:
                    queue.append(target)
                continue
            if "text/html" not in r.headers.get("Content-Type", ""):
                continue
            parser = PageParser()
            parser.feed(r.text)
            for url in parser.links + [action or path for action, _ in parser.forms]:
                ok, target = same_origin(self.base, url)
                if ok:
                    self.note(target, "crawl")
                    if not target.startswith("/static/"):
                        queue.append(target)
            for src in parser.scripts:
                ok, target = same_origin(self.base, src)
                if ok:
                    self.note(target, "crawl")
                    self.js_files.add(target)

    # -- phase 3
    def analyse_js(self):
        for js in sorted(self.js_files):
            r = self.send(self.sessions["anonymous"], "GET", js)
            if r.status_code != 200:
                continue
            strings, comments = split_js(r.text)
            in_code = {s for s in strings if QUOTED_PATH.match(s) and len(s) > 1 and not s.startswith("//")}
            for path in in_code:
                self.note(path, "js-code")
            for comment in comments:
                for path in API_IN_TEXT.findall(comment):
                    if normalize(path) not in {normalize(p) for p in in_code}:
                        self.note(path, "js-comment")

    # -- verification (OPTIONS -> Allow header)
    def verify(self):
        new = []
        for template, sources in list(self.candidates.items()):
            if template in self.endpoints:
                self.endpoints[template]["sources"] |= sources
                continue
            if template in self.not_found:
                continue
            r = self.send(self.sessions["anonymous"], "OPTIONS", concrete(template))
            if r.status_code in EXISTS:
                allow = sorted(m.strip() for m in r.headers.get("Allow", "").split(",") if m.strip())
                self.endpoints[template] = {"sources": set(sources), "allow": allow}
                new.append(template)
            else:
                self.not_found.add(template)
        return new

    # -- phase 5
    def probe_ids(self, templates):
        for template in templates:
            if kind(template) == "static" or template.endswith(ID) or template == "/":
                continue
            r = self.send(self.sessions["anonymous"], "OPTIONS", concrete(template) + "/" + PROBE_ID)
            if r.status_code in EXISTS:
                self.note(template + "/" + PROBE_ID, "id-probe")

    # -- phase 4
    def fuzz(self, rounds=4):
        done = set()
        for _ in range(rounds):
            prefixes = set()
            for template in list(self.endpoints) + list(self.not_found):
                if kind(template) != "static":
                    prefixes |= parents(template)
            prefixes |= {normalize(p) for p in self.robots if p.endswith("/")}
            prefixes = {p for p in prefixes if p not in done and not p.startswith("/static")}
            if not prefixes:
                break
            for prefix in sorted(prefixes):
                done.add(prefix)
                for word in self.words:
                    path = f"{concrete(prefix).rstrip('/')}/{word}"
                    if normalize(path) in self.endpoints or any(w in word for w in NEVER_GET):
                        continue
                    r = self.send(self.sessions["anonymous"], "GET", path)
                    if r.status_code in EXISTS:
                        self.note(path, "wordlist")
            self.probe_ids(self.verify())
            self.verify()

    # -- access matrix
    def access_matrix(self):
        for template, info in self.endpoints.items():
            info["access"] = {}
            if kind(template) == "static" or "GET" not in info["allow"] or any(w in template for w in NEVER_GET):
                continue
            for identity in IDENTITIES:
                r = self.send(self.sessions[identity], "GET", concrete(template))
                cell = str(r.status_code)
                if r.status_code in REDIRECTS:
                    cell += "->" + urlparse(r.headers.get("Location", "")).path
                info["access"][identity] = cell

    def run(self):
        started = time.time()
        self.sessions["anonymous"] = self.session()
        print("[1/6] robots.txt");            self.read_robots()
        print("[2/6] login + crawl as each identity")
        self.login_all()
        for identity in IDENTITIES:
            self.crawl(identity)
        print("[3/6] JavaScript analysis");    self.analyse_js()
        print("[4/6] verify candidates (OPTIONS) + ID probing")
        self.probe_ids(self.verify())
        self.verify()
        print("[5/6] wordlist fuzzing under every parent path"); self.fuzz()
        print("[6/6] access matrix (GET as each identity)");     self.access_matrix()
        return time.time() - started


# --------------------------------------------------------------------------- reporting

def load_flask_routes(path):
    """Parse the output of `flask routes` into {template: set(methods)}."""
    routes = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 3 or cols[0] in ("Endpoint",) or set(cols[0]) <= {"-"}:
            continue
        rule = re.sub(r"<(?:int:)?[^>]+>", ID, cols[-1])
        if rule.startswith("/static/"):
            continue
        routes.setdefault(rule, set()).update(m.strip() for m in cols[1].split(","))
    return routes


def functional(methods):
    return [m for m in methods if m not in ("HEAD", "OPTIONS")]


def summarise_sources(sources):
    order = ["well-known", "crawl", "js-code", "js-comment", "robots", "wordlist", "id-probe"]
    return ", ".join(s for s in order if s in sources)


def build_report(e, elapsed, routes):
    endpoints = sorted((t for t in e.endpoints if kind(t) != "static"), key=lambda t: (kind(t) != "page", t))
    static = sorted(t for t in e.endpoints if kind(t) == "static")
    rows = []
    for t in endpoints:
        info = e.endpoints[t]
        rows.append({
            "path": t,
            "methods": functional(info["allow"]),
            "kind": kind(t),
            "found_by": summarise_sources(info["sources"]),
            "hidden": info["sources"] <= HIDDEN_SOURCES,
            "access": info.get("access", {}),
        })

    lines = [
        "WanderWays - black-box endpoint enumeration (raw tool output)",
        "=" * 78,
        f"Target     : {e.base}",
        f"Run at     : {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Requests   : {e.requests} in {elapsed:.1f}s - GET/HEAD/OPTIONS only, no data modified",
        f"Identities : anonymous, " + ", ".join(f"{r} ({u})" for r, (u, _) in ACCOUNTS.items()),
        f"Wordlist   : {len(e.words)} words",
        f"robots.txt : disallows {', '.join(e.robots) or '-'}",
        f"JS files   : {', '.join(sorted(e.js_files)) or '-'}",
        "",
        f"Endpoints found: {len(rows)} ({sum(r['hidden'] for r in rows)} hidden = not referenced by the UI code)",
        "",
        f"{'#':>2}  {'METHODS':<18} {'PATH':<30} {'FOUND BY':<40} "
        + " ".join(f"{x.upper():<15}" for x in IDENTITIES),
        "-" * 156,
    ]
    for i, r in enumerate(rows, 1):
        a = r["access"]
        flag = " *" if r["hidden"] else ""
        lines.append(
            f"{i:>2}  {', '.join(r['methods']):<18} {r['path'] + flag:<30} {r['found_by']:<40} "
            + " ".join(f"{a.get(x, '-'):<15}" for x in IDENTITIES)
        )
    lines += ["", "* = hidden endpoint (found only via robots.txt, JS comments, wordlist or ID probing)",
              "Access cells are the GET status per identity (302->/x = redirect). '-' = GET not allowed / not sent.",
              "", "Static assets: " + ", ".join(static)]

    coverage = None
    if routes:
        found_paths = {r["path"] for r in rows}
        missing = sorted(set(routes) - found_paths)
        extra = sorted(found_paths - set(routes))
        method_gaps = {
            p: sorted(set(functional(routes[p])) - set(functional(e.endpoints[p]["allow"])))
            for p in routes if p in e.endpoints
        }
        method_gaps = {p: m for p, m in method_gaps.items() if m}
        coverage = {
            "routes_in_source": len(routes),
            "found": len(set(routes) & found_paths),
            "missing": missing,
            "extra": extra,
            "method_gaps": method_gaps,
        }
        lines += ["", "Coverage check against `flask routes` (white-box ground truth)",
                  f"  paths found : {coverage['found']}/{coverage['routes_in_source']}"
                  f" ({100 * coverage['found'] / coverage['routes_in_source']:.0f}%)",
                  f"  missed      : {', '.join(missing) or 'none'}",
                  f"  not in source (false positives): {', '.join(extra) or 'none'}",
                  f"  method gaps : {method_gaps or 'none'}"]

    data = {
        "target": e.base,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "requests_sent": e.requests,
        "methods_used": ["GET", "HEAD", "OPTIONS"],
        "robots_disallow": e.robots,
        "javascript_files": sorted(e.js_files),
        "endpoints": rows,
        "static_assets": static,
        "coverage": coverage,
    }
    return "\n".join(lines) + "\n", data


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Black-box endpoint enumeration for the WanderWays lab.")
    parser.add_argument("--base", default="http://127.0.0.1:5000", help="target (default: %(default)s)")
    parser.add_argument("--wordlist", type=Path, default=here / "wordlist.txt")
    parser.add_argument("--proxy", help="send everything through a proxy, e.g. http://127.0.0.1:8081")
    parser.add_argument("--routes", type=Path, help="`flask routes` output, to measure coverage")
    parser.add_argument("--out", type=Path, help="directory for enumeration_report.txt / .json")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every request")
    args = parser.parse_args()

    host = urlparse(args.base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("Refusing to scan a non-local target: this tool is for the local lab only.")

    words = [w.strip() for w in args.wordlist.read_text(encoding="utf-8").splitlines()
             if w.strip() and not w.startswith("#")]
    scanner = Enumerator(args.base, args.proxy, words, args.verbose)
    try:
        elapsed = scanner.run()
    except requests.ConnectionError as exc:
        sys.exit(f"Cannot reach {args.base} - start the app first (flask --app wanderways run).\n{exc}")

    routes = load_flask_routes(args.routes) if args.routes else None
    text, data = build_report(scanner, elapsed, routes)
    print("\n" + text)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "enumeration_report.txt").write_text(text, encoding="utf-8")
        (args.out / "enumeration_report.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Saved {args.out / 'enumeration_report.txt'} and enumeration_report.json")


if __name__ == "__main__":
    main()
