"""Individual DNS checks. Each returns a ``CheckResult``."""
import re


def parse_tags(record: str) -> dict:
    """Parse 'k=v; k2=v2' tag lists (DKIM, DMARC, MTA-STS, TLS-RPT, BIMI)."""
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def starts_with_version(txt: str, version: str) -> bool:
    """True if a TXT record starts with e.g. 'v=DMARC1' (case-insensitive, spaces tolerated)."""
    return re.match(r"^\s*v\s*=\s*" + re.escape(version) + r"\s*(;|$|\s)", txt, re.I) is not None
