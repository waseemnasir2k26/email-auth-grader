"""Command line: grade | bulk | headers | mcp."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .dnsio import DnsPythonResolver, Resolver, ZoneResolver, clean_domain
from .headers import check_headers, render_headers_text
from .report import check_status, render
from .score import grade_domain, sorted_findings


def make_resolver(zone_path=None, timeout=5.0) -> Resolver:
    if zone_path:
        return ZoneResolver.from_json(zone_path)
    return DnsPythonResolver(timeout=timeout)


def _selectors(s):
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def build_parser():
    p = argparse.ArgumentParser(prog="email-auth-grader",
                                description="Grade a domain's cold-email readiness from public DNS.")
    p.add_argument("--version", action="version", version=f"email-auth-grader {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--selectors", help="comma-separated DKIM selectors to probe instead of the built-in list")
        sp.add_argument("--no-http", action="store_true", help="skip the MTA-STS policy HTTPS fetch")
        sp.add_argument("--zone", help="read DNS answers from a recorded zone JSON file instead of live DNS")
        sp.add_argument("--timeout", type=float, default=5.0, help="DNS timeout seconds (default 5)")

    g = sub.add_parser("grade", help="grade one domain")
    g.add_argument("domain")
    g.add_argument("--format", choices=["text", "json", "md", "html"], default="text")
    g.add_argument("--fail-under", type=int, default=None, help="exit 1 if the score is below this (for CI)")
    g.add_argument("--out", help="write the report to this file instead of stdout")
    common(g)

    b = sub.add_parser("bulk", help="grade every domain in a CSV (column 'domain', or the first column)")
    b.add_argument("csv")
    b.add_argument("--out", required=True, help="results CSV to write")
    b.add_argument("--workers", type=int, default=4, help="domains graded in parallel (default 4)")
    common(b)

    h = sub.add_parser("headers", help="check List-Unsubscribe (RFC 8058) and DKIM d= alignment in a saved .eml")
    h.add_argument("eml")
    h.add_argument("--format", choices=["text", "json"], default="text")

    m = sub.add_parser("mcp", help="run the stdio MCP server")
    m.add_argument("--zone", help="serve answers from a recorded zone JSON (offline demos and tests)")
    return p


def read_domains(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = [r for r in csv.reader(fh) if r and any(c.strip() for c in r)]
    if not rows:
        return []
    head = [c.strip().lower() for c in rows[0]]
    if "domain" in head:
        idx, rows = head.index("domain"), rows[1:]
    else:
        idx = 0
        if head[0] in ("website", "url", "site", "domains"):
            rows = rows[1:]
    out, seen = [], set()
    for r in rows:
        if idx < len(r) and r[idx].strip():
            out.append(r[idx].strip())
    return [d for d in out if not (d.lower() in seen or seen.add(d.lower()))]


BULK_COLS = ["domain", "grade", "score", "mx", "spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "bimi",
             "spf_lookups", "dmarc_policy", "findings", "top_fix", "error"]


def bulk_row(raw, resolver, selectors, check_http):
    try:
        r = grade_domain(raw, resolver, selectors, check_http)
    except ValueError as e:
        return {"domain": raw, "grade": "", "score": "", "error": str(e)}
    top = next((f for f in sorted_findings(r.findings) if f.points > 0), None)
    return {
        "domain": r.domain, "grade": r.letter, "score": r.score,
        **{c.replace("-", "_"): check_status(r, c) for c in ("mx", "spf", "dkim", "dmarc", "mta-sts", "tls-rpt", "bimi")},
        "spf_lookups": r.data.get("spf", {}).get("lookups", ""),
        "dmarc_policy": r.data.get("dmarc", {}).get("policy") or "none-published",
        "findings": sum(1 for f in r.findings if f.points > 0),
        "top_fix": top.title if top else "", "error": "",
    }


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "mcp":
        from .mcp_server import serve
        return serve(ZoneResolver.from_json(args.zone) if args.zone else None)
    if args.cmd == "headers":
        with open(args.eml, "rb") as fh:
            r = check_headers(fh.read())
        print(json.dumps(r, indent=2) if args.format == "json" else render_headers_text(r))
        return 0
    resolver = make_resolver(args.zone, args.timeout)
    sels = _selectors(args.selectors)
    if args.cmd == "grade":
        try:
            clean_domain(args.domain)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        r = grade_domain(args.domain, resolver, sels, not args.no_http)
        text = render(r, args.format)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        else:
            print(text)
        return 1 if args.fail_under is not None and r.score < args.fail_under else 0
    # bulk
    domains = read_domains(args.csv)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        rows = list(ex.map(lambda d: bulk_row(d, resolver, sels, not args.no_http), domains))
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=BULK_COLS, restval="")
        w.writeheader()
        w.writerows(rows)
    graded = [r for r in rows if r["grade"]]
    print(f"graded {len(graded)}/{len(rows)} domains -> {args.out}")
    for L in "ABCDF":
        n = sum(1 for r in graded if r["grade"] == L)
        if n:
            print(f"  {L}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
