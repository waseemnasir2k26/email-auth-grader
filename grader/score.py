"""Scoring and orchestration: run every check, total the penalties, pick the letter."""
from __future__ import annotations

import datetime as _dt

from . import __version__
from .checks.dkim import check_dkim
from .checks.dmarc import check_dmarc
from .checks.mtasts import check_bimi, check_mtasts, check_tlsrpt
from .checks.mx import check_mx
from .checks.spf import check_spf
from .dnsio import Resolver, clean_domain
from .models import CheckResult, Finding, Fix, Report

CRITICAL_CAP = 59   # any critical finding caps the score at F


def letter_for(score: int) -> str:
    for floor, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= floor:
            return letter
    return "F"


def total(findings) -> int:
    score = 100 - sum(f.points for f in findings)
    if any(f.severity == "critical" for f in findings):
        score = min(score, CRITICAL_CAP)
    return max(0, min(100, score))


def send_guidance(domain, mx_data, dmarc_data, score) -> list:
    """Conservative cold-email guidance. These are rules of thumb, NOT checks."""
    g = [
        f"Send cold outreach from a separate subdomain or secondary domain (for example mail.{domain}), not "
        "your primary domain, so a reputation problem cannot hit your everyday mail.",
        "Warm up new mailboxes: start with a handful of messages a day and raise volume gradually over "
        "3-4 weeks. Keep daily volume per mailbox modest; there is no official number, so treat any figure "
        "as a rule of thumb.",
        "Watch Google Postmaster Tools. Google's published guidance is to keep the user-reported spam rate "
        "under 0.30% (and ideally under 0.10%).",
        "Add a working unsubscribe/opt-out to every campaign. Bulk marketing mail to Gmail and Yahoo needs "
        "one-click unsubscribe (RFC 8058): check a real message with `email-auth-grader headers message.eml`.",
        "Authenticate with the same domain you put in the From header (alignment) and verify DNS changes "
        "before launching a campaign.",
    ]
    if dmarc_data.get("policy") == "none":
        g.append("Keep DMARC at p=none only while you collect reports; plan the move to quarantine.")
    if score < 80:
        g.append("Fix the high and medium findings above before sending any volume from this domain.")
    return g


def _stamp(now: _dt.datetime) -> str:
    return now.strftime("%Y%m%dT%H%M%S")


def grade_domain(domain, resolver: Resolver, selectors=None, check_http=True, now=None) -> Report:
    domain = clean_domain(domain)
    now = now or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    generated = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    apex = resolver.query(domain, "TXT")
    if apex.status == "nxdomain":
        f = Finding("dns", "critical", "Domain does not exist (NXDOMAIN)",
                    "The name has no DNS records at all, so no mail can be authenticated.", 100)
        return Report(domain, 0, "F", [f], [], [], {"dns": {"status": "nxdomain"}}, generated, __version__)

    results = {}
    results["mx"] = check_mx(domain, resolver)
    results["spf"] = check_spf(domain, resolver, results["mx"].data)
    results["dkim"] = check_dkim(domain, resolver, selectors)
    results["dmarc"] = check_dmarc(domain, resolver)
    results["mta-sts"] = check_mtasts(domain, resolver, results["mx"].data["hosts"], check_http, _stamp(now))
    results["tls-rpt"] = check_tlsrpt(domain, resolver)
    results["bimi"] = check_bimi(domain, resolver, results["dmarc"].data)

    findings = [f for r in results.values() for f in r.findings]
    score = total(findings)
    records, seen = [], set()
    for f in sorted(findings, key=lambda x: -x.points):
        if f.fix and f.points > 0 and (f.fix.type, f.fix.name, f.fix.value) not in seen:
            seen.add((f.fix.type, f.fix.name, f.fix.value))
            records.append(f.fix)
    data = {k: r.data for k, r in results.items()}
    return Report(domain, score, letter_for(score), findings, records,
                  send_guidance(domain, results["mx"].data, results["dmarc"].data, score),
                  data, generated, __version__)


def sorted_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}
    return sorted(findings, key=lambda f: (order[f.severity], -f.points))
