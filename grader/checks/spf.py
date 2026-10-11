"""SPF: single record, RFC 7208 DNS-lookup limit (10), void lookups (2), all-qualifier."""
from __future__ import annotations

import re

from ..models import CheckResult, Fix

LOOKUP_LIMIT = 10
VOID_LIMIT = 2


def is_spf(txt: str) -> bool:
    return re.match(r"^v=spf1(\s|$)", txt.strip(), re.I) is not None


def get_spf_records(domain, resolver):
    ans = resolver.query(domain, "TXT")
    return [r.strip() for r in ans.records if is_spf(r)], ans


class Walk:
    def __init__(self):
        self.lookups = 0
        self.voids = 0
        self.errors = []
        self.has_ptr = False
        self.includes = []
        self.truncated = False


def _target(term_body: str, default: str) -> str:
    """Extract domain-spec from 'a', 'a:dom', 'a:dom/24', 'mx/24'."""
    if ":" in term_body:
        return term_body.split(":", 1)[1].split("/")[0] or default
    return default


def _walk(domain, record, resolver, w: Walk, visited, depth=0):
    """Walk one SPF record, returning its effective all-qualifier (or None)."""
    all_q = None
    redirect = None
    for term in record.split()[1:]:
        q = "+"
        t = term
        if t[0] in "+-~?":
            q, t = t[0], t[1:]
        low = t.lower()
        name = re.split(r"[:=/]", low, maxsplit=1)[0]
        if w.lookups > 30:  # hard stop on pathological records
            w.truncated = True
            return all_q
        if name == "all":
            all_q = q
        elif name == "include":
            target = _target(t, "")
            w.lookups += 1
            w.includes.append(target)
            if not target or "%" in target:
                continue
            if target.lower() in visited:
                w.errors.append(f"include loop at {target}")
                continue
            recs, ans = get_spf_records(target, resolver)
            if ans.status == "error":
                w.errors.append(f"DNS error resolving include:{target}")
            elif not recs:
                w.errors.append(f"include:{target} has no SPF record (permerror)")
                if ans.status in ("nxdomain", "nodata"):
                    w.voids += 1
            elif len(recs) > 1:
                w.errors.append(f"include:{target} has multiple SPF records (permerror)")
            else:
                _walk(target, recs[0], resolver, w, visited | {target.lower()}, depth + 1)
        elif name in ("a", "mx", "exists"):
            w.lookups += 1
            target = _target(t, domain)
            if "%" in target:
                continue
            if name == "mx":
                void = not resolver.query(target, "MX").records
            elif name == "exists":
                void = not resolver.query(target, "A").records
            else:
                void = not (resolver.query(target, "A").records or resolver.query(target, "AAAA").records)
            if void:
                w.voids += 1
        elif name == "ptr":
            w.lookups += 1
            w.has_ptr = True
        elif name == "redirect" and "=" in t:
            redirect = t.split("=", 1)[1]
    if redirect and all_q is None:
        w.lookups += 1
        w.includes.append(f"redirect={redirect}")
        if "%" not in redirect and redirect.lower() not in visited:
            recs, ans = get_spf_records(redirect, resolver)
            if len(recs) == 1:
                return _walk(redirect, recs[0], resolver, w, visited | {redirect.lower()}, depth + 1)
            w.errors.append(f"redirect={redirect} does not point at exactly one SPF record (permerror)")
            if not recs and ans.status in ("nxdomain", "nodata"):
                w.voids += 1
    return all_q


def merge_spf(records, add_includes=(), qualifier="~"):
    """Merge one or more SPF records into a single record (exact paste-in text).

    Terms are de-duplicated in order, any ``all`` terms dropped, new includes
    appended, and one final ``<qualifier>all`` added. ``redirect=`` is kept only
    if no mechanism list could replace it.
    """
    terms, seen = [], set()
    for rec in records:
        for term in rec.split()[1:]:
            if re.match(r"^[+\-~?]?all$", term, re.I):
                continue
            key = term.lower()
            if key not in seen:
                seen.add(key)
                terms.append(term)
    for inc in add_includes:
        if inc.lower() not in seen:
            seen.add(inc.lower())
            terms.append(inc)
    return " ".join(["v=spf1"] + terms + [f"{qualifier}all"])


def starter_spf(provider_include=None):
    inc = provider_include or "include:<your-sending-provider>"
    return f"v=spf1 {inc} ~all"


def check_spf(domain, resolver, mx_data=None) -> CheckResult:
    res = CheckResult()
    records, ans = get_spf_records(domain, resolver)
    mx_data = mx_data or {}
    prov_inc = mx_data.get("provider_spf_include")
    res.data = {"records": records, "lookups": 0, "void_lookups": 0, "all": None}
    if ans.status == "error":
        res.add("spf", "info", "SPF lookup failed", "DNS error while resolving TXT; try again.", 0)
        return res
    if not records:
        starter = starter_spf(prov_inc)
        res.add("spf", "high", "No SPF record",
                "Gmail and Yahoo require SPF or DKIM for all senders, and both for bulk senders. "
                "Publish one SPF TXT record at the domain apex listing every service that sends as this domain.",
                25, Fix("TXT", domain, starter,
                        "Starter record" + (f" for {mx_data.get('provider')} mail" if prov_inc else "")
                        + ". Add one include: per sending service (cold-email platform, CRM, etc.)."))
        return res
    if len(records) > 1:
        merged = merge_spf(records)
        res.add("spf", "high", f"{len(records)} SPF records (permerror)",
                "RFC 7208 allows exactly one SPF record per name; receivers treat several as a permanent error, "
                "so SPF fails for every message.", 20,
                Fix("TXT", domain, merged, "Merged into one record; delete the other SPF TXT records. "
                    "Re-check the all-qualifier before publishing."))
    rec = records[0]
    w = Walk()
    all_q = _walk(domain, rec, resolver, w, {domain.lower()})
    res.data.update({"lookups": w.lookups, "void_lookups": w.voids, "all": all_q, "includes": w.includes,
                     "errors": w.errors, "record": rec})
    # all qualifier
    if all_q == "+":
        merged = merge_spf(records, qualifier="~")
        res.add("spf", "critical", "SPF ends in +all (anyone can send as you)",
                "+all authorises every server on the internet. Replace it with ~all or -all.", 30,
                Fix("TXT", domain, merged, "Same mechanisms with ~all. Move to -all once DMARC reports are clean."))
    elif all_q == "?":
        merged = merge_spf(records, qualifier="~")
        res.add("spf", "medium", "SPF ends in ?all (neutral)",
                "?all gives receivers no signal. Use ~all (soft fail) or -all (hard fail).", 12,
                Fix("TXT", domain, merged, "Same mechanisms with ~all."))
    elif all_q is None and not any(i.startswith("redirect=") for i in w.includes):
        merged = merge_spf(records, qualifier="~")
        res.add("spf", "medium", "SPF has no 'all' terminator",
                "Without a terminating all (or redirect=) the result for unlisted senders is neutral.", 8,
                Fix("TXT", domain, merged, "Same mechanisms with a closing ~all."))
    elif all_q == "~":
        res.add("spf", "pass", "SPF ends in ~all (soft fail)",
                "Accepted practice while DMARC does the enforcing. -all is stricter once reports are clean.", 0)
    else:
        res.add("spf", "pass", f"SPF ends in {all_q}all", "", 0)
    # lookup count
    if w.lookups > LOOKUP_LIMIT:
        res.add("spf", "high", f"SPF needs {w.lookups} DNS lookups (limit {LOOKUP_LIMIT})",
                "RFC 7208 section 4.6.4 caps include/a/mx/ptr/exists/redirect at 10 per check. Over the limit the "
                "result is permerror and SPF fails. Remove unused includes, move bulk senders to a subdomain, or "
                "flatten includes to ip4:/ip6: ranges (and re-flatten when vendors change them).", 20)
    elif w.lookups == LOOKUP_LIMIT:
        res.add("spf", "low", f"SPF uses {w.lookups}/{LOOKUP_LIMIT} DNS lookups",
                "Exactly at the limit: adding one more include will break SPF.", 3)
    elif w.lookups >= 8:
        res.add("spf", "info", f"SPF uses {w.lookups}/{LOOKUP_LIMIT} DNS lookups",
                "Close to the limit; leave headroom before adding a sending service.", 0)
    else:
        res.add("spf", "pass", f"SPF uses {w.lookups}/{LOOKUP_LIMIT} DNS lookups", "", 0)
    if w.voids > VOID_LIMIT:
        res.add("spf", "medium", f"{w.voids} void SPF lookups (limit {VOID_LIMIT})",
                "Lookups that return nothing count against a limit of 2 (RFC 7208 section 4.6.4). Remove "
                "mechanisms that point at names that no longer exist.", 10)
    for e in w.errors:
        res.add("spf", "high", "SPF include problem", e, 10)
    if w.has_ptr:
        res.add("spf", "low", "SPF uses the ptr mechanism",
                "RFC 7208 says ptr SHOULD NOT be used: it is slow and unreliable.", 3)
    if w.truncated:
        res.add("spf", "info", "SPF walk truncated", "Stopped counting after 30 lookups.", 0)
    return res
