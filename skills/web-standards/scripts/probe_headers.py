#!/usr/bin/env python3
"""Live HTTP header probe for a deployed site (cache.*, sec.*, perf.13, net.20). Read-only GETs.

    python probe_headers.py --url https://example.com [--path /blog] [--api /api/health] [--format md|json|sarif] [--strict]

Only contacts the URL you pass. Generic User-Agent, no cookies, no auth. Run it against
sites you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

import _bootstrap  # noqa: F401
from wclib.findings import Report
from wclib.rules import RuleBook

SKILL = Path(__file__).resolve().parents[1]
UA = "stack-audit-probe/0.1 (+header audit)"


def fetch(url: str, accept_encoding: str = "br, gzip") -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": accept_encoding, "Accept": "*/*"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as res:
            body = res.read(400_000)
            return res.status, {k.lower(): v for k, v in res.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, b""


def http_version(url: str) -> str | None:
    if not shutil.which("curl"):
        return None
    try:
        out = subprocess.run(["curl", "-sI", "--max-time", "15", "-A", UA, url], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.match(r"HTTP/([\d.]+)", out)
    return m.group(1) if m else None


def max_age(cc: str, key: str = "max-age") -> int | None:
    m = re.search(rf"(?:^|[,\s]){key}=(\d+)", cc)
    return int(m.group(1)) if m else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--path", action="append", default=[], help="Extra HTML paths to probe")
    ap.add_argument("--api", action="append", default=[], help="API GET paths to probe for ETag/Cache-Control")
    ap.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    base = args.url.rstrip("/") + "/"
    if urlparse(base).scheme not in ("http", "https"):
        print("error: --url must be http(s)", file=sys.stderr)
        return 2
    rb = RuleBook(SKILL)
    report = Report(tool="probe_headers", root=base)

    def add(rule, msg, url, **kw):
        report.add(rb.make(rule, msg, file=url, confidence="high", **kw))

    try:
        status, h, body = fetch(base)
    except (urllib.error.URLError, OSError) as exc:
        print(f"error: could not fetch {base}: {exc}", file=sys.stderr)
        return 2
    report.meta["status"] = status
    html_urls = [base] + [urljoin(base, p.lstrip("/")) for p in args.path]

    for i, url in enumerate(html_urls):
        st, hh, bb = (status, h, body) if i == 0 else fetch(url)
        cc = hh.get("cache-control", "")
        ma = max_age(cc)
        if not cc:
            add("cache.01", "HTML response has no Cache-Control header", url)
        elif ma and ma > 3600 and "no-cache" not in cc:
            add("cache.09", f"HTML cached in browsers for {ma}s: new deploys won't be picked up (Cache-Control: {cc})", url,
                fix_hint="HTML: no-cache / max-age=0 (CDN: s-maxage + stale-while-revalidate)")
        vary = hh.get("vary", "")
        if "cookie" in vary.lower() and ("public" in cc or max_age(cc, "s-maxage")):
            add("cache.08", f"Cacheable HTML varies on Cookie (CDN hit rate collapses): Vary: {vary}", url)
        if "private" not in cc and "no-store" not in cc and re.search(r"set-cookie", " ".join(hh)) and ("public" in cc or max_age(cc, "s-maxage")):
            add("cache.08", "Public-cacheable response sets a cookie (risk of caching personalized data)", url, severity="error")
        enc = hh.get("content-encoding", "")
        if st == 200 and enc not in ("br", "gzip", "zstd") and len(bb) > 1400:
            add("perf.13", f"HTML not compressed (Content-Encoding: {enc or 'none'})", url, fix_hint="Enable Brotli/gzip at the proxy/CDN")
        if i == 0:
            security_headers(hh, url, add)
    # first hashed static asset referenced by the page
    m = re.search(rb"(/_next/static/[^\"'\s>]+\.(?:js|css))", body) or re.search(rb"src=\"(/[^\"]+\.[0-9a-f]{6,}\.(?:js|css))\"", body)
    if m:
        asset = urljoin(base, m.group(1).decode())
        st, ah, ab = fetch(asset)
        acc = ah.get("cache-control", "")
        if not ("immutable" in acc and (max_age(acc) or 0) >= 31536000):
            add("cache.01", f"Hashed static asset not cached as immutable for a year (Cache-Control: {acc or 'none'})", asset,
                fix_hint="public, max-age=31536000, immutable")
        if ah.get("content-encoding", "") not in ("br", "gzip", "zstd") and len(ab) > 1400:
            add("perf.13", "Static JS/CSS not compressed", asset)
    else:
        report.skipped.append("No hashed static asset found in the HTML to probe")
    for p in args.api:
        url = urljoin(base, p.lstrip("/"))
        st, ah, _ = fetch(url)
        if "etag" not in ah and "last-modified" not in ah and "no-store" not in ah.get("cache-control", ""):
            add("net.03", "API GET response has no ETag/Last-Modified (no cheap revalidation)", url, severity="info")
        if not ah.get("cache-control"):
            add("net.02", "API response has no Cache-Control", url, severity="info")
    ver = http_version(base)
    if ver:
        report.meta["http_version"] = ver
        if ver.startswith("1") and "h3" not in h.get("alt-svc", ""):
            add("net.20", f"Served over HTTP/{ver} with no HTTP/3 (alt-svc) advertised", base, severity="info")
    elif "h3" not in h.get("alt-svc", ""):
        report.skipped.append("HTTP version not determined (curl not found); no HTTP/3 alt-svc header seen")
    report.not_checked.append("CDN purge behaviour, offline/service-worker behaviour, and authenticated pages (not probed)")
    print(report.render(args.format))
    return 1 if args.strict and report.has_errors() else 0


def security_headers(h: dict[str, str], url: str, add) -> None:
    hsts = h.get("strict-transport-security", "")
    if url.startswith("https") and not hsts:
        add("sec.13", "No Strict-Transport-Security header", url, fix_hint="max-age=63072000; includeSubDomains; preload")
    elif hsts and (max_age(hsts) or 0) < 31536000:
        add("sec.13", f"HSTS max-age below one year ({hsts})", url, severity="info")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("sec.19", "Missing X-Content-Type-Options: nosniff", url)
    if not h.get("referrer-policy"):
        add("sec.19", "Missing Referrer-Policy", url)
    pp = h.get("permissions-policy", "")
    if not pp:
        add("sec.15", "Missing Permissions-Policy", url)
    elif "interest-cohort" in pp:
        add("sec.15", "Permissions-Policy lists obsolete interest-cohort", url, severity="info")
    csp = h.get("content-security-policy", "")
    if not csp:
        add("sec.03", "No enforced Content-Security-Policy" + (" (Report-Only present)" if h.get("content-security-policy-report-only") else ""), url)
    elif "'unsafe-eval'" in csp:
        add("sec.03", "CSP allows 'unsafe-eval'", url)
    if "frame-ancestors" not in csp and h.get("x-frame-options", "").upper() not in ("DENY", "SAMEORIGIN"):
        add("sec.05", "No framing protection (CSP frame-ancestors / X-Frame-Options)", url)
    if h.get("x-powered-by"):
        add("sec.19", f"X-Powered-By discloses the stack ({h['x-powered-by']})", url, severity="info",
            fix_hint="poweredByHeader: false in next.config")


if __name__ == "__main__":
    sys.exit(main())
