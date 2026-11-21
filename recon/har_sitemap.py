#!/usr/bin/env python3
"""Turn a proxy capture (HAR file) into a readable HTTP history and site map.

Works with HAR files from mitmproxy (--set hardump=...) or a browser's
DevTools "Save all as HAR". Output mirrors Burp's Proxy > HTTP history and
Target > Site map views, as plain text that can live in the repository.

Usage:
    python recon/har_sitemap.py docs/evidence/proxy/wanderways_capture.har --out docs/evidence/proxy
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse


def template(path):
    return "/".join("{id}" if seg.isdigit() else seg for seg in path.split("/")) or "/"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("har", type=Path)
    parser.add_argument("--out", type=Path, help="directory for proxy_history.txt and proxy_sitemap.txt")
    args = parser.parse_args()

    log = json.loads(args.har.read_text(encoding="utf-8"))["log"]
    entries = log["entries"]
    creator = log.get("creator", {})

    history = [
        f"Proxy HTTP history - {len(entries)} requests captured by "
        f"{creator.get('name', '?')} {creator.get('version', '')} ({args.har.name})",
        "",
        f"{'#':>3}  {'TIME (UTC)':<12} {'METHOD':<7} {'STATUS':<6} {'LENGTH':>7}  {'MIME':<18} URL",
        "-" * 110,
    ]
    sitemap = defaultdict(lambda: {"methods": set(), "statuses": set(), "hits": 0})
    for i, entry in enumerate(entries, 1):
        req, res = entry["request"], entry["response"]
        url = urlparse(req["url"])
        mime = (res.get("content", {}).get("mimeType") or "").split(";")[0]
        length = res.get("content", {}).get("size", 0)
        clock = re.sub(r"^.*T(\d\d:\d\d:\d\d(?:\.\d{3})?).*$", r"\1", entry.get("startedDateTime", ""))
        target = url.path + (f"?{url.query}" if url.query else "")
        history.append(
            f"{i:>3}  {clock:<12} {req['method']:<7} {res['status']:<6} {length:>7}  {mime:<18} {target}"
        )
        node = sitemap[(f"{url.scheme}://{url.netloc}", template(url.path))]
        node["methods"].add(req["method"])
        node["statuses"].add(res["status"])
        node["hits"] += 1

    hosts = sorted({host for host, _ in sitemap})
    tree = ["Proxy site map (observed traffic only - hidden endpoints never appear here)", ""]
    for host in hosts:
        tree.append(host)
        # every observed path plus its parent folders, sorted so children follow parents
        nodes = set()
        for _, path in (k for k in sitemap if k[0] == host):
            segs = tuple(s for s in path.split("/") if s)
            nodes.update(segs[:i] for i in range(0 if not segs else 1, len(segs) + 1))
        for segs in sorted(nodes):
            path = "/" + "/".join(segs)
            indent = "    " * max(len(segs) - 1, 0)
            label = f"{indent}/{segs[-1]}" if segs else "/"
            node = sitemap.get((host, path))
            if node is None:
                tree.append(f"  {label}")
                continue
            tree.append(
                f"  {label:<44}{', '.join(sorted(node['methods'])):<12}"
                f" status {', '.join(map(str, sorted(node['statuses']))):<10} hits {node['hits']}"
            )
        tree.append("")
    tree.append(f"{len(sitemap)} unique paths observed in {len(entries)} requests.")

    history_text, tree_text = "\n".join(history) + "\n", "\n".join(tree) + "\n"
    print(tree_text)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "proxy_history.txt").write_text(history_text, encoding="utf-8")
        (args.out / "proxy_sitemap.txt").write_text(tree_text, encoding="utf-8")
        print(f"Saved {args.out / 'proxy_history.txt'} and {args.out / 'proxy_sitemap.txt'}")


if __name__ == "__main__":
    main()
