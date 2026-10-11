"""Check a saved message (.eml): List-Unsubscribe (RFC 8058) and DKIM-Signature d= alignment.

This inspects header presence, coverage and alignment. It does NOT verify DKIM
signatures cryptographically and does not look anything up in DNS.
"""
from __future__ import annotations

import email
import email.policy
import re
from email.utils import parseaddr

from . import __version__
from .checks import parse_tags
from .models import CheckResult
from .score import letter_for, total

ONE_CLICK = "list-unsubscribe=one-click"


def _org(domain: str) -> str:
    """Approximate organisational domain: last two labels. No public-suffix list is shipped,
    so multi-part TLDs such as co.uk are treated as the registry (documented limitation)."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def aligned(from_domain: str, d: str, strict: bool = False) -> bool:
    from_domain, d = from_domain.lower(), d.lower()
    if strict:
        return from_domain == d
    return _org(from_domain) == _org(d)


def _fold(v) -> str:
    return re.sub(r"\s+", " ", str(v)).strip()


def check_headers(eml_text) -> dict:
    msg = email.message_from_string(eml_text, policy=email.policy.compat32) if isinstance(eml_text, str) \
        else email.message_from_bytes(eml_text, policy=email.policy.compat32)
    res = CheckResult()
    # From
    _, addr = parseaddr(_fold(msg.get("From", "")))
    from_domain = addr.rsplit("@", 1)[1].lower() if "@" in addr else ""
    if not from_domain:
        res.add("headers", "high", "No parseable From address", "DMARC alignment is judged against the From domain.", 20)
    else:
        res.add("headers", "pass", f"From domain: {from_domain}", "", 0)
    # DKIM-Signature
    sigs = []
    for raw in msg.get_all("DKIM-Signature", []):
        t = parse_tags(_fold(raw))
        sigs.append({"d": t.get("d", "").lower(), "s": t.get("s", ""), "a": t.get("a", "").lower(),
                     "h": [x.strip().lower() for x in t.get("h", "").split(":") if x.strip()]})
    if not sigs:
        res.add("headers", "high", "No DKIM-Signature header",
                "Unsigned mail fails DKIM and cannot pass DMARC through DKIM. Gmail and Yahoo require DKIM for bulk senders.", 25)
    else:
        al = [s for s in sigs if from_domain and s["d"] and aligned(from_domain, s["d"])]
        if al:
            res.add("headers", "pass", f"DKIM d={al[0]['d']} aligns with From {from_domain}",
                    "Relaxed alignment (organisational domain match, approximated without a public-suffix list).", 0)
        else:
            ds = ", ".join(s["d"] or "?" for s in sigs)
            res.add("headers", "high", f"DKIM d= ({ds}) does not align with From ({from_domain or '?'})",
                    "DMARC can only pass through DKIM when the signing domain (d=) matches the From domain. Many "
                    "cold-email platforms sign with their own domain by default: enable custom-domain DKIM.", 20)
        for s in sigs:
            if s["a"] == "rsa-sha1":
                res.add("headers", "medium", f"DKIM selector {s['s']} signs with rsa-sha1",
                        "RFC 8301 forbids rsa-sha1 signing. Use rsa-sha256.", 8)
    # List-Unsubscribe
    lu = [_fold(v) for v in msg.get_all("List-Unsubscribe", [])]
    lup = [_fold(v) for v in msg.get_all("List-Unsubscribe-Post", [])]
    https_url = mailto = False
    all_urls = []
    if not lu:
        res.add("headers", "medium", "No List-Unsubscribe header",
                "Gmail and Yahoo require one-click unsubscribe for bulk marketing mail, and recommending an opt-out "
                "also protects cold outreach from spam reports.", 10)
    else:
        for v in lu:
            urls = re.findall(r"<([^>]+)>", v)
            all_urls += urls
            https_url = https_url or any(u.lower().startswith("https://") for u in urls)
            mailto = mailto or any(u.lower().startswith("mailto:") for u in urls)
            if any(u.lower().startswith("http://") for u in urls):
                res.add("headers", "medium", "List-Unsubscribe uses a plain http:// URL",
                        "RFC 8058 one-click needs an https URL.", 5)
        if not all_urls:
            res.add("headers", "medium", "List-Unsubscribe has no <...> URIs", "Wrap each URI in angle brackets.", 8)
        if lup:
            if not any(ONE_CLICK in v.lower().replace(" ", "") for v in lup):
                res.add("headers", "medium", "List-Unsubscribe-Post value is wrong",
                        "RFC 8058 requires exactly: List-Unsubscribe-Post: List-Unsubscribe=One-Click", 8)
            elif not https_url:
                res.add("headers", "high", "One-click header without an https URL",
                        "List-Unsubscribe-Post needs an https URL in List-Unsubscribe.", 10)
            else:
                res.add("headers", "pass", "RFC 8058 one-click unsubscribe headers present", "", 0)
            covered = [s for s in sigs if "list-unsubscribe" in s["h"] and "list-unsubscribe-post" in s["h"]]
            if sigs and not covered:
                res.add("headers", "medium", "DKIM does not sign the unsubscribe headers",
                        "RFC 8058 requires List-Unsubscribe and List-Unsubscribe-Post to be covered by a DKIM "
                        "signature (h= tag).", 8)
        elif https_url:
            res.add("headers", "medium", "https unsubscribe link without List-Unsubscribe-Post",
                    "Add 'List-Unsubscribe-Post: List-Unsubscribe=One-Click' (and sign it) to enable one-click "
                    "unsubscribe as Gmail and Yahoo require for bulk senders.", 8)
        else:
            res.add("headers", "low", "mailto-only List-Unsubscribe",
                    "Works for ordinary opt-out, but one-click (RFC 8058) needs an https URL.", 3)
    if not msg.get("Message-ID"):
        res.add("headers", "low", "No Message-ID header", "Receivers may add one for you, which looks sloppy.", 2)
    # Receiver-side Authentication-Results, if the .eml was saved from a mailbox
    ar = " ".join(_fold(v) for v in msg.get_all("Authentication-Results", []))
    verdicts = dict(re.findall(r"\b(spf|dkim|dmarc)=(\w+)", ar.lower())) if ar else {}
    for k, v in verdicts.items():
        if v in ("fail", "softfail", "permerror", "temperror", "none"):
            res.add("headers", "medium", f"Receiver recorded {k}={v}",
                    "Taken from the Authentication-Results header your mailbox provider added.", 10)
        elif v == "pass":
            res.add("headers", "pass", f"Receiver recorded {k}=pass", "", 0)
    score = total(res.findings)
    return {
        "version": __version__,
        "from_domain": from_domain,
        "score": score,
        "letter": letter_for(score),
        "signatures": sigs,
        "list_unsubscribe": lu,
        "list_unsubscribe_post": lup,
        "authentication_results": verdicts,
        "findings": [f.to_dict() for f in res.findings],
        "note": "Header presence, coverage and alignment only. DKIM signatures are not cryptographically verified.",
    }


def render_headers_text(r: dict) -> str:
    out = [f"email-auth-grader headers  |  From: {r['from_domain'] or '?'}",
           f"Grade: {r['letter']} ({r['score']}/100)", ""]
    for f in sorted(r["findings"], key=lambda x: -x["points"]):
        tag = f["severity"].upper()
        out.append(f"[{tag}] {f['title']}")
        if f["detail"]:
            out.append(f"       {f['detail']}")
    out += ["", r["note"]]
    return "\n".join(out)
