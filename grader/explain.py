"""Plain-English explanation of a pasted SPF / DKIM / DMARC / MTA-STS / TLS-RPT / BIMI record."""
from __future__ import annotations

import re

from .checks import parse_tags
from .checks.dkim import parse_dkim
from .checks.dmarc import suggest_step

SPF_Q = {"+": "pass", "-": "fail (hard)", "~": "softfail", "?": "neutral"}
DMARC_TAGS = {
    "p": "policy for the domain", "sp": "policy for subdomains", "pct": "share of failing mail the policy applies to",
    "rua": "where aggregate reports go", "ruf": "where forensic reports go", "adkim": "DKIM alignment (r=relaxed, s=strict)",
    "aspf": "SPF alignment (r=relaxed, s=strict)", "fo": "failure-report options", "ri": "report interval seconds",
}


def detect_kind(rec: str) -> str:
    r = rec.strip().lower()
    for prefix, kind in (("v=spf1", "spf"), ("v=dmarc1", "dmarc"), ("v=dkim1", "dkim"), ("v=stsv1", "mta-sts"),
                         ("v=tlsrptv1", "tls-rpt"), ("v=bimi1", "bimi")):
        if re.match(r"^v\s*=\s*" + prefix[2:], r):
            return kind
    if re.search(r"\bp=[A-Za-z0-9+/=\s]{20,}", rec):
        return "dkim"
    return "unknown"


def explain_record(rec: str, kind: str = "") -> dict:
    kind = (kind or detect_kind(rec)).lower()
    lines = []
    if kind == "spf":
        for term in rec.split()[1:]:
            q = term[0] if term[0] in SPF_Q else "+"
            body = term.lstrip("+-~?")
            name = re.split(r"[:=/]", body, maxsplit=1)[0].lower()
            counts = name in ("include", "a", "mx", "ptr", "exists", "redirect")
            if name == "all":
                lines.append(f"{term}: everything else gets '{SPF_Q[q]}'.")
            elif name in ("ip4", "ip6"):
                lines.append(f"{term}: authorises that address range (no DNS lookup).")
            else:
                lines.append(f"{term}: {name} mechanism, result '{SPF_Q[q]}'"
                             + (" - costs 1 of the 10 allowed DNS lookups." if counts else "."))
    elif kind == "dmarc":
        for k, v in parse_tags(rec).items():
            if k != "v":
                lines.append(f"{k}={v}: {DMARC_TAGS.get(k, 'tag')}")
        lines.append("Next step: " + suggest_step(rec)["why"])
    elif kind == "dkim":
        d = parse_dkim(rec)
        lines.append(f"key type {d['key_type']}" + (f", {d['bits']}-bit" if d["bits"] else ""))
        if d["revoked"]:
            lines.append("p= is empty: this key is revoked.")
        if d["testing"]:
            lines.append("t=y: testing mode, receivers may ignore failures.")
        if d["bits"] and d["key_type"] == "rsa" and d["bits"] < 2048:
            lines.append("Below 2048 bits: plan a rotation to 2048-bit RSA.")
    elif kind in ("mta-sts", "tls-rpt", "bimi"):
        for k, v in parse_tags(rec).items():
            lines.append(f"{k}={v}")
    else:
        lines.append("Not recognised as SPF, DKIM, DMARC, MTA-STS, TLS-RPT or BIMI.")
    return {"kind": kind, "tags": parse_tags(rec) if kind != "spf" else {}, "explanation": lines}
