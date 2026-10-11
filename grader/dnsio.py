"""DNS and HTTP access behind small injectable interfaces.

Checks only ever call ``resolver.query(name, rdtype)`` and
``resolver.get(url)``. Production uses dnspython + urllib; tests and the
``--zone`` option use ``ZoneResolver`` which reads recorded JSON zones, so CI
never touches live DNS.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSAnswer:
    status: str                      # ok | nxdomain | nodata | error
    records: list = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok" and bool(self.records)


def norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


class Resolver:
    """Interface. Subclass and implement ``query`` (and ``get`` for MTA-STS)."""

    def query(self, name: str, rdtype: str) -> DNSAnswer:  # pragma: no cover
        raise NotImplementedError

    def get(self, url: str, timeout: float = 5.0):  # pragma: no cover
        """Return (status_code | None, body, error_text)."""
        return None, "", "HTTP not supported by this resolver"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class DnsPythonResolver(Resolver):
    """Live resolver backed by dnspython (the single runtime dependency)."""

    def __init__(self, timeout: float = 5.0, nameservers: Optional[list] = None):
        import dns.resolver

        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout
        self._r.timeout = min(timeout, 3.0)
        if nameservers:
            self._r.nameservers = nameservers

    def query(self, name, rdtype):
        import dns.exception
        import dns.resolver

        try:
            ans = self._r.resolve(norm(name), rdtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer("nxdomain")
        except dns.resolver.NoAnswer:
            return DNSAnswer("nodata")
        except dns.exception.DNSException as e:
            return DNSAnswer("error", [], type(e).__name__)
        out = []
        for rr in ans:
            if rdtype == "TXT":
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            elif rdtype == "MX":
                out.append(f"{rr.preference} {rr.exchange.to_text().rstrip('.') or '.'}")
            else:
                out.append(rr.to_text())
        return DNSAnswer("ok", out)

    def get(self, url, timeout=5.0):
        # RFC 8461: MTA-STS policy fetches must not follow redirects.
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers={"User-Agent": "email-auth-grader"})
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, r.read(65536).decode("utf-8", "replace"), ""
        except urllib.error.HTTPError as e:
            return e.code, "", f"HTTP {e.code}"
        except Exception as e:  # DNS failure, TLS error, timeout ...
            return None, "", f"{type(e).__name__}: {e}"


class ZoneResolver(Resolver):
    """Offline resolver reading a recorded zone.

    JSON shape::

        {"zone": {"example.com": {"TXT": ["v=spf1 -all"], "MX": ["10 mx.example.com"]}},
         "https": {"https://mta-sts.example.com/.well-known/mta-sts.txt":
                   {"status": 200, "body": "version: STSv1\\n..."}},
         "errors": ["broken.example.com"]}

    A name that is absent is NXDOMAIN; a name present without the requested
    type is NODATA.
    """

    def __init__(self, zone=None, https=None, errors=None):
        self.zone = {norm(k): v for k, v in (zone or {}).items()}
        self.https = https or {}
        self.errors = {norm(e) for e in (errors or [])}

    @classmethod
    def from_json(cls, path_or_dict):
        if isinstance(path_or_dict, dict):
            d = path_or_dict
        else:
            with open(path_or_dict, encoding="utf-8") as fh:
                d = json.load(fh)
        return cls(d.get("zone"), d.get("https"), d.get("errors"))

    def query(self, name, rdtype):
        n = norm(name)
        if n in self.errors:
            return DNSAnswer("error", [], "simulated")
        rrs = self.zone.get(n)
        if rrs is None:
            return DNSAnswer("nxdomain")
        vals = rrs.get(rdtype.upper())
        if not vals:
            return DNSAnswer("nodata")
        return DNSAnswer("ok", list(vals))

    def get(self, url, timeout=5.0):
        r = self.https.get(url)
        if r is None:
            return None, "", "connection failed (not in recorded zone)"
        return r.get("status", 200), r.get("body", ""), ""


class RecordingResolver(Resolver):
    """Wraps a live resolver and captures every answer in ZoneResolver format."""

    def __init__(self, inner: Resolver):
        self.inner = inner
        self.zone, self.https, self.errors = {}, {}, set()

    def query(self, name, rdtype):
        a = self.inner.query(name, rdtype)
        n = norm(name)
        if a.status == "error":
            self.errors.add(n)
        elif a.status in ("ok", "nodata"):
            slot = self.zone.setdefault(n, {})
            if a.status == "ok":
                slot[rdtype.upper()] = list(a.records)
        return a

    def get(self, url, timeout=5.0):
        st, body, err = self.inner.get(url, timeout)
        self.https[url] = {"status": st or 0, "body": body}
        return st, body, err

    def dump(self) -> dict:
        return {"zone": self.zone, "https": self.https, "errors": sorted(self.errors)}


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def clean_domain(raw: str) -> str:
    """Accept 'Example.com', 'https://example.com/x', 'me@example.com'; return an ascii domain."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"not a valid domain: {raw!r}")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"not a valid domain: {raw!r}")
    return d
