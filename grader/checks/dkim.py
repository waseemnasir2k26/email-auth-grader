"""DKIM: probe common selectors, parse the public key, report key length."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor

from ..models import CheckResult
from . import parse_tags

# Selectors used by common mailbox providers and sending platforms. A domain can
# use ANY selector, so a miss is a hint, never proof (see the finding text).
SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "mandrill", "mailjet", "zoho", "amazonses", "sendgrid", "smtpapi", "mail", "dkim",
    "smtp", "email", "mxvault", "pm", "cm", "protonmail", "protonmail2", "protonmail3",
    "fm1", "fm2", "fm3", "sig1", "mte1", "everlytickey1", "hostingermail-a", "hostingermail-b",
    "hostingermail-c", "hs1", "hs2",
]

_ZERO = bytes([0])


def _tlv(b: bytes, i: int):
    """Minimal DER reader: returns (tag, content, index_after)."""
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, b[i:i + n], i + n


def rsa_bits(p_b64: str):
    """Modulus size in bits from a DER SubjectPublicKeyInfo (or bare RSAPublicKey); None if unparseable."""
    try:
        der = base64.b64decode(p_b64 + "=" * (-len(p_b64) % 4))
        tag, body, _ = _tlv(der, 0)
        if tag != 0x30:
            return None
        t2, c2, nxt = _tlv(body, 0)
        if t2 == 0x02:                      # bare RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
            n = c2
        else:                               # SPKI: SEQUENCE { algId, BIT STRING { RSAPublicKey } }
            t3, bits, _ = _tlv(body, nxt)
            if t3 != 0x03:
                return None
            t4, rsa, _ = _tlv(bits[1:], 0)
            t5, n, _ = _tlv(rsa, 0)
            if t4 != 0x30 or t5 != 0x02:
                return None
        n = n.lstrip(_ZERO)
        return (len(n) - 1) * 8 + n[0].bit_length()
    except Exception:
        return None


def parse_dkim(txt: str) -> dict:
    tags = parse_tags(txt)
    kt = tags.get("k", "rsa").lower()
    p = "".join(tags.get("p", "").split())
    info = {"key_type": kt, "revoked": p == "", "testing": "y" in tags.get("t", "").lower().split(":"),
            "bits": None, "tags": tags}
    if p:
        info["bits"] = 256 if kt == "ed25519" else rsa_bits(p)
    return info


def _probe(domain, resolver, sel):
    ans = resolver.query(f"{sel}._domainkey.{domain}", "TXT")
    for txt in ans.records:
        if "p=" in txt.replace(" ", "").lower() or txt.lower().startswith("v=dkim1"):
            d = parse_dkim(txt)
            d["selector"] = sel
            return d
    return None


def check_dkim(domain, resolver, selectors=None, workers=8) -> CheckResult:
    res = CheckResult()
    sels = list(dict.fromkeys(selectors or SELECTORS))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        found = [f for f in ex.map(lambda s: _probe(domain, resolver, s), sels) if f]
    keys = [{k: v for k, v in f.items() if k != "tags"} for f in found]
    res.data = {"probed": len(sels), "found": keys}
    live = [f for f in found if not f["revoked"]]
    if not live:
        extra = " (every key found is revoked: empty p=)" if found else ""
        res.add("dkim", "medium", f"No DKIM key found on {len(sels)} probed selectors{extra}",
                "Gmail and Yahoo require DKIM for bulk senders. DKIM selectors are arbitrary, so this probe can "
                "miss a custom one: read the s= tag of a real message's DKIM-Signature, then re-run with "
                "--selectors <name> (or run the `headers` command on a saved .eml). If your sending platform has "
                "not given you a DKIM record yet, enable domain authentication there and publish what it shows.",
                10)
        return res
    names = ", ".join(f["selector"] for f in live)
    res.add("dkim", "pass", f"DKIM key found: {names}", "", 0)
    weak = [f for f in live if f["key_type"] == "rsa" and f["bits"] and f["bits"] < 2048]
    unk = [f for f in live if f["key_type"] == "rsa" and f["bits"] is None]
    if any(f["bits"] < 1024 for f in weak):
        res.add("dkim", "high", "DKIM key shorter than 1024 bits",
                "Verifiers may reject signatures from keys under 1024 bits (RFC 8301). Rotate to 2048-bit RSA.", 20)
    elif weak:
        s = ", ".join(f"{f['selector']} ({f['bits']}-bit)" for f in weak)
        res.add("dkim", "medium", f"1024-bit DKIM key: {s}",
                "1024-bit RSA still verifies but is considered weak. Generate a 2048-bit key in your sending "
                "platform, publish it under a NEW selector, switch signing over, then retire the old one. "
                "The key value comes from your platform, so no paste-in record can be generated here.", 10)
    for f in unk:
        res.add("dkim", "low", f"Could not read key length for selector {f['selector']}",
                "The p= value did not parse as an RSA public key.", 2)
    for f in live:
        if f["testing"]:
            res.add("dkim", "low", f"Selector {f['selector']} is in testing mode (t=y)",
                    "Receivers may ignore the result. Remove t=y once signing is confirmed.", 3)
    return res
