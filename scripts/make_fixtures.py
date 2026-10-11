"""Regenerate fixtures/*.json: SYNTHETIC zones on reserved '.example' names.

Real RSA public keys are generated with the `openssl` binary so the DKIM key-length
parser is exercised on genuine DER. Run: python scripts/make_fixtures.py
"""
import base64
import json
import os
import subprocess

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


def pubkey(bits):
    priv = subprocess.run(["openssl", "genrsa", str(bits)], capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "rsa", "-pubout", "-outform", "DER"], input=priv,
                         capture_output=True, check=True).stdout
    return base64.b64encode(der).decode()


def policy(mode, mx):
    return "version: STSv1\nmode: %s\n%smax_age: 604800\n" % (mode, "".join("mx: %s\n" % m for m in mx))


def base_zone(d, key, dmarc, spf=None, mx=("aspmx.l.google.com", "alt1.aspmx.l.google.com")):
    z = {
        d: {"TXT": [spf or "v=spf1 include:_spf.google.com -all"],
            "MX": ["1 %s" % mx[0], "5 %s" % mx[1]]},
        "_spf.google.com": {"TXT": ["v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"]},
        "google._domainkey.%s" % d: {"TXT": ["v=DKIM1; k=rsa; p=%s" % key]},
    }
    if dmarc:
        z["_dmarc.%s" % d] = {"TXT": [dmarc]}
    return z


def write(name, doc):
    with open(os.path.join(ROOT, name), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def main():
    k2048, k1024 = pubkey(2048), pubkey(1024)
    mx = ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]

    d = "perfect.example"
    z = base_zone(d, k2048, "v=DMARC1; p=reject; rua=mailto:dmarc@perfect.example; adkim=s; aspf=s")
    z["_mta-sts." + d] = {"TXT": ["v=STSv1; id=20260101T000000"]}
    z["_smtp._tls." + d] = {"TXT": ["v=TLSRPTv1; rua=mailto:tls@perfect.example"]}
    z["default._bimi." + d] = {"TXT": ["v=BIMI1; l=https://perfect.example/logo.svg"]}
    write("perfect.json", {"zone": z, "https": {
        "https://mta-sts.%s/.well-known/mta-sts.txt" % d: {"status": 200, "body": policy("enforce", mx)}}})

    d = "spf-overlimit.example"
    z = base_zone(d, k2048, "v=DMARC1; p=quarantine; rua=mailto:dmarc@spf-overlimit.example",
                  spf="v=spf1 include:s1.vendor.example include:s2.vendor.example include:s3.vendor.example "
                      "include:s4.vendor.example include:s5.vendor.example ~all")
    for i in (1, 2, 3):
        z["s%d.vendor.example" % i] = {"TXT": ["v=spf1 include:n%da.vendor.example include:n%db.vendor.example -all" % (i, i)]}
        for sfx in "ab":
            z["n%d%s.vendor.example" % (i, sfx)] = {"TXT": ["v=spf1 ip4:192.0.2.%d -all" % i]}
    for i in (4, 5):
        z["s%d.vendor.example" % i] = {"TXT": ["v=spf1 ip4:198.51.100.%d -all" % i]}
    write("spf-overlimit.json", {"zone": z})

    d = "no-dmarc.example"
    write("no-dmarc.json", {"zone": base_zone(d, k2048, None)})

    d = "dmarc-none.example"
    write("dmarc-none.json", {"zone": base_zone(d, k2048, "v=DMARC1; p=none")})

    d = "dkim-1024.example"
    write("dkim-1024.json", {"zone": base_zone(d, k1024, "v=DMARC1; p=reject; rua=mailto:r@dkim-1024.example")})

    d = "mtasts-mismatch.example"
    z = base_zone(d, k2048, "v=DMARC1; p=reject; rua=mailto:r@mtasts-mismatch.example")
    z["_mta-sts." + d] = {"TXT": ["v=STSv1; id=1"]}
    write("mtasts-mismatch.json", {"zone": z, "https": {
        "https://mta-sts.%s/.well-known/mta-sts.txt" % d: {"status": 200, "body": policy("enforce", ["mail.old-host.example"])}}})

    # a small multi-domain zone for bulk mode and the MCP subprocess test
    big = {}
    for f in ("perfect", "no-dmarc", "dmarc-none"):
        with open(os.path.join(ROOT, f + ".json"), encoding="utf-8") as fh:
            j = json.load(fh)
        big.setdefault("zone", {}).update(j["zone"])
        big.setdefault("https", {}).update(j.get("https", {}))
    write("bulk-demo.json", big)


if __name__ == "__main__":
    main()
