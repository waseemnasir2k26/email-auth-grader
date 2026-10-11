"""DMARC: presence, policy, pct, rua, alignment, and a safe next-step ladder."""
from __future__ import annotations

from ..models import CheckResult, Fix
from . import parse_tags, starts_with_version

PCT_LADDER = [10, 25, 50, 100]


def find_dmarc(domain, resolver):
    """Return (record|None, host_where_found, count, dns_status). Subdomains inherit from a parent."""
    labels = domain.split(".")
    cands = [".".join(labels[i:]) for i in range(0, max(len(labels) - 1, 1))]
    last = None
    for c in cands:
        ans = resolver.query(f"_dmarc.{c}", "TXT")
        last = ans
        recs = [r.strip() for r in ans.records if starts_with_version(r, "DMARC1")]
        if recs:
            return recs[0], c, len(recs), ans.status
        if ans.status == "error":
            return None, None, 0, "error"
    return None, None, 0, last.status if last else "nxdomain"


def starter_dmarc(domain):
    return Fix("TXT", f"_dmarc.{domain}",
               f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; adkim=r; aspf=r",
               "Monitoring-only starter. Create the dmarc-reports mailbox (or point rua= at a DMARC report "
               "processor) so aggregate reports have somewhere to land.")


def _rebuild(record, **changes):
    """Return ``record`` with tags replaced (value None drops the tag); tag order preserved."""
    tags = parse_tags(record)
    for k, v in changes.items():
        if v is None:
            tags.pop(k, None)
        else:
            tags[k] = v
    order = ["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo"]
    keys = [k for k in order if k in tags] + [k for k in tags if k not in order]
    return "; ".join(f"{k}={tags[k]}" for k in keys)


def suggest_step(record, domain="<domain>"):
    """Safe next move for a DMARC record (``None`` = no record). Returns dict(step, record_change, why)."""
    if not record:
        return {"step": "publish_monitoring", "target": "p=none; rua=mailto:...",
                "record": starter_dmarc(domain).value,
                "why": "No policy yet. Start in monitoring mode and collect aggregate (rua) reports before enforcing."}
    t = parse_tags(record)
    p = t.get("p", "").lower()
    pct = int(t["pct"]) if t.get("pct", "").isdigit() else 100
    if p not in ("none", "quarantine", "reject"):
        return {"step": "fix_syntax", "target": "p=none|quarantine|reject",
                "record": None,
                "why": "The p= tag is missing or invalid, so receivers ignore the whole record."}
    if p == "none":
        if not t.get("rua"):
            return {"step": "add_rua", "target": f"rua=mailto:dmarc-reports@{domain}",
                    "record": _rebuild(record, rua=f"mailto:dmarc-reports@{domain}"),
                    "why": "p=none without rua= gives you no reports, so you cannot tell what is safe to enforce."}
        return {"step": "to_quarantine_10", "target": "p=quarantine; pct=10",
                "record": _rebuild(record, p="quarantine", pct="10"),
                "why": "After 2-4 weeks of clean aggregate reports (all legitimate senders aligned), "
                       "quarantine a small slice first."}
    if p == "quarantine":
        nxt = next((x for x in PCT_LADDER if x > pct), None)
        if nxt is not None:
            return {"step": f"raise_pct_{nxt}", "target": f"p=quarantine; pct={nxt}",
                    "record": _rebuild(record, pct=str(nxt)),
                    "why": "Raise the enforced share gradually while watching reports for legitimate failures."}
        return {"step": "to_reject_25", "target": "p=reject; pct=25",
                "record": _rebuild(record, p="reject", pct="25"),
                "why": "Quarantine at 100% with clean reports: move to reject on a slice, then to full reject."}
    # reject
    if pct < 100:
        return {"step": "reject_full", "target": "p=reject (drop pct)",
                "record": _rebuild(record, pct=None),
                "why": "Reject is already live on a slice; remove pct to enforce on all mail."}
    return {"step": "done", "target": "p=reject", "record": None,
            "why": "Already at full enforcement. Keep reading rua reports and add sp=reject if subdomains send nothing."}


def check_dmarc(domain, resolver) -> CheckResult:
    res = CheckResult()
    rec, where, count, status = find_dmarc(domain, resolver)
    res.data = {"record": rec, "found_at": where, "count": count, "policy": None, "pct": None}
    if status == "error":
        res.add("dmarc", "info", "DMARC lookup failed", "DNS error while resolving _dmarc TXT; try again.", 0)
        return res
    if not rec:
        res.add("dmarc", "high", "No DMARC record",
                "Gmail and Yahoo require a DMARC record (p=none is enough) from anyone sending 5,000+ messages a "
                "day to their users, and cold-email domains are judged on it regardless of volume. Publish the "
                "starter record, read the reports for 2-4 weeks, then tighten.", 25, starter_dmarc(domain))
        return res
    if count > 1:
        res.add("dmarc", "high", f"{count} DMARC records",
                "More than one v=DMARC1 record makes DMARC invalid. Keep exactly one.", 15)
    t = parse_tags(rec)
    p = t.get("p", "").lower()
    pct = int(t["pct"]) if t.get("pct", "").isdigit() else 100
    res.data.update({"policy": p or None, "pct": pct, "rua": t.get("rua"), "adkim": t.get("adkim", "r"),
                     "aspf": t.get("aspf", "r"), "sp": t.get("sp")})
    inherited = f" (inherited from _dmarc.{where})" if where != domain else ""
    if p not in ("none", "quarantine", "reject"):
        res.add("dmarc", "high", "DMARC record has no valid p= policy",
                "The p= tag is required and must be none, quarantine or reject. Receivers ignore the record.", 20)
        return res
    if p == "none":
        res.add("dmarc", "medium", f"DMARC policy is p=none{inherited}",
                "Monitoring only: spoofed mail is not blocked. Fine as step one, but plan the move to quarantine "
                "and reject once reports are clean.", 12)
    elif p == "quarantine":
        res.add("dmarc", "pass", f"DMARC policy is p=quarantine{inherited}", "", 0)
    else:
        res.add("dmarc", "pass", f"DMARC policy is p=reject{inherited}", "", 0)
    if p != "none" and pct < 100:
        res.add("dmarc", "low", f"DMARC enforces only pct={pct}",
                "Only that share of failing mail gets the policy. Raise pct as reports stay clean.", 5)
    rua = t.get("rua", "")
    if not rua:
        res.add("dmarc", "low", "DMARC has no rua= reporting address",
                "Without aggregate reports you cannot see who sends as your domain or what fails alignment.", 5,
                Fix("TXT", f"_dmarc.{where}", _rebuild(rec, rua=f"mailto:dmarc-reports@{domain}"),
                    "Same record plus a reporting address. Create the mailbox or swap in a report processor."))
    else:
        for addr in [a.strip() for a in rua.split(",")]:
            if addr.lower().startswith("mailto:") and "@" in addr:
                rdom = addr.rsplit("@", 1)[1].split("!")[0].lower()
                if rdom != domain and not rdom.endswith("." + domain) and not domain.endswith("." + rdom):
                    res.add("dmarc", "info", f"rua sends reports to external domain {rdom}",
                            f"The receiving domain must publish {domain}._report._dmarc.{rdom} TXT "
                            f"'v=DMARC1' to authorise it (RFC 7489 section 7.1); report processors usually do.", 0)
    if t.get("adkim", "r").lower() == "s" or t.get("aspf", "r").lower() == "s":
        res.add("dmarc", "info", "Strict alignment (adkim/aspf=s)",
                "Strict alignment is safer against spoofing but breaks mail sent from subdomains of the "
                "From domain. Confirm every sender uses the exact From domain.", 0)
    step = suggest_step(rec, domain)
    res.data["next_step"] = step
    if step["step"] == "done":
        res.add("dmarc", "pass", "DMARC is at full enforcement", step["why"], 0)
    elif step["step"] not in ("fix_syntax", "add_rua"):
        new = step.get("record")
        res.add("dmarc", "info", f"Safe next DMARC step: {step['target']}", step["why"], 0,
                Fix("TXT", f"_dmarc.{where}", new, "Change only when the condition in the finding is met.")
                if new else None)
    return res
