"""MTA-STS (RFC 8461) TXT + policy fetch, TLS-RPT (RFC 8460) and BIMI."""
from __future__ import annotations

import fnmatch

from ..models import CheckResult, Fix
from . import parse_tags, starts_with_version


def parse_policy(body: str) -> dict:
    out = {"mx": []}
    for line in body.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "mx":
            out["mx"].append(v.lower())
        else:
            out[k] = v
    return out


def mx_matches(pattern: str, host: str) -> bool:
    """RFC 8461 section 4.1: '*.example.com' matches exactly one extra leading label."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and fnmatch.fnmatchcase(host, pattern)
    return pattern == host


def policy_template(mx_hosts, mode="testing"):
    lines = ["version: STSv1", f"mode: {mode}"]
    lines += [f"mx: {h}" for h in (mx_hosts or ["<your-mx-host>"])]
    lines.append("max_age: 86400")
    return "\n".join(lines) + "\n"


def check_mtasts(domain, resolver, mx_hosts=(), check_http=True, stamp="20260101T000000") -> CheckResult:
    res = CheckResult()
    ans = resolver.query(f"_mta-sts.{domain}", "TXT")
    recs = [r for r in ans.records if starts_with_version(r, "STSv1")]
    res.data = {"txt": recs[0] if recs else None, "policy": None}
    if ans.status == "error":
        res.add("mta-sts", "info", "MTA-STS lookup failed", "DNS error; try again.", 0)
        return res
    if not recs:
        res.add("mta-sts", "low", "No MTA-STS record",
                "Optional but expected on a mature sending domain: it forces TLS for inbound mail and is what "
                "TLS-RPT reports on. Publish the TXT record and host the policy file over HTTPS "
                "(start in testing mode).", 3,
                Fix("TXT", f"_mta-sts.{domain}", f"v=STSv1; id={stamp}",
                    f"Then serve this file at https://mta-sts.{domain}/.well-known/mta-sts.txt "
                    f"(a valid HTTPS certificate for mta-sts.{domain} is required):\n"
                    + policy_template(mx_hosts)))
        return res
    if len(recs) > 1:
        res.add("mta-sts", "medium", "Multiple MTA-STS TXT records", "Publish exactly one.", 5)
    tags = parse_tags(recs[0])
    if not tags.get("id"):
        res.add("mta-sts", "medium", "MTA-STS TXT has no id=", "id= is required; change it whenever the policy changes.", 5)
    if not check_http:
        res.add("mta-sts", "info", "MTA-STS policy fetch skipped (--no-http)", "TXT record present.", 0)
        return res
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    status, body, err = resolver.get(url)
    if status != 200:
        res.add("mta-sts", "medium", "MTA-STS policy file not reachable",
                f"GET {url} -> {status or err}. The TXT record promises a policy; senders that cannot fetch it "
                "ignore MTA-STS. Redirects are not allowed and the certificate must be valid.", 8)
        return res
    pol = parse_policy(body)
    res.data["policy"] = pol
    if pol.get("version") != "STSv1":
        res.add("mta-sts", "medium", "MTA-STS policy has no 'version: STSv1'", "", 5)
    mode = pol.get("mode", "").lower()
    unmatched = [h for h in mx_hosts if not any(mx_matches(p, h) for p in pol["mx"])]
    if unmatched:
        res.add("mta-sts", "high", "MTA-STS policy does not match your MX records",
                "In enforce mode senders would refuse to deliver to: " + ", ".join(unmatched) +
                f". Policy lists: {', '.join(pol['mx']) or 'nothing'}. Update the mx: lines (and bump the id= "
                "in the TXT record).", 15 if mode == "enforce" else 8,
                Fix("FILE", url, policy_template(mx_hosts, mode if mode in ("testing", "enforce") else "testing"),
                    "Replace the policy file with this, then change the id= value in the _mta-sts TXT record."))
    if mode == "enforce":
        if not unmatched:
            res.add("mta-sts", "pass", "MTA-STS policy in enforce mode, MX hosts match", "", 0)
    elif mode == "testing":
        res.add("mta-sts", "low", "MTA-STS is in testing mode",
                "Testing mode reports failures but does not enforce TLS. Move to enforce once TLS-RPT is clean.", 2)
    elif mode == "none":
        res.add("mta-sts", "low", "MTA-STS mode is none", "The policy is switched off.", 3)
    else:
        res.add("mta-sts", "medium", "MTA-STS policy has no valid mode", "mode must be enforce, testing or none.", 5)
    try:
        if int(pol.get("max_age", "0")) < 86400:
            res.add("mta-sts", "low", "MTA-STS max_age under one day",
                    "RFC 8461 recommends at least a day (weeks once in enforce mode).", 1)
    except ValueError:
        res.add("mta-sts", "low", "MTA-STS max_age is not a number", "", 1)
    return res


def check_tlsrpt(domain, resolver) -> CheckResult:
    res = CheckResult()
    ans = resolver.query(f"_smtp._tls.{domain}", "TXT")
    recs = [r for r in ans.records if starts_with_version(r, "TLSRPTv1")]
    res.data = {"record": recs[0] if recs else None}
    if ans.status == "error":
        res.add("tls-rpt", "info", "TLS-RPT lookup failed", "DNS error; try again.", 0)
    elif not recs:
        res.add("tls-rpt", "low", "No TLS-RPT record",
                "TLS-RPT sends you daily reports about failed TLS deliveries to your domain. Pairs with MTA-STS.", 2,
                Fix("TXT", f"_smtp._tls.{domain}", f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
                    "Create the tls-reports mailbox or point rua= at a report processor."))
    elif "rua=" not in recs[0].lower():
        res.add("tls-rpt", "low", "TLS-RPT record has no rua=", "Add rua=mailto:... or rua=https://...", 1)
    else:
        res.add("tls-rpt", "pass", "TLS-RPT record present", recs[0], 0)
    return res


def check_bimi(domain, resolver, dmarc_data=None) -> CheckResult:
    res = CheckResult()
    ans = resolver.query(f"default._bimi.{domain}", "TXT")
    recs = [r for r in ans.records if starts_with_version(r, "BIMI1")]
    res.data = {"record": recs[0] if recs else None}
    if not recs:
        res.add("bimi", "info", "No BIMI record (optional)",
                "BIMI shows your logo in supporting inboxes. It needs DMARC at quarantine/reject with pct=100, "
                "an SVG Tiny PS logo and (for Gmail's checkmark) a VMC/CMC certificate. Not needed for deliverability.", 0)
        return res
    t = parse_tags(recs[0])
    if not t.get("l", "").lower().startswith("https://"):
        res.add("bimi", "low", "BIMI l= must be an https:// URL to an SVG", "", 2)
    else:
        res.add("bimi", "pass", "BIMI record present", recs[0], 0)
    d = dmarc_data or {}
    if d.get("policy") not in ("quarantine", "reject") or (d.get("pct") or 100) < 100:
        res.add("bimi", "low", "BIMI published but DMARC is not enforcing at pct=100",
                "Mailbox providers ignore BIMI unless DMARC is quarantine/reject at pct=100.", 3)
    return res
