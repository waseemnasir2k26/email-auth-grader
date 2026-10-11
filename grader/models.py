"""Plain data classes shared by every check."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITIES = ("pass", "info", "low", "medium", "high", "critical")


@dataclass
class Fix:
    """An exact DNS record (or file) to publish."""

    type: str          # TXT, FILE ...
    name: str          # DNS name, or URL for FILE
    value: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    check: str                 # spf, dkim, dmarc, mx, mta-sts, tls-rpt, bimi, headers
    severity: str              # one of SEVERITIES
    title: str
    detail: str = ""
    points: int = 0            # penalty subtracted from 100
    fix: Optional[Fix] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.fix is None:
            d["fix"] = None
        return d


@dataclass
class CheckResult:
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, check, severity, title, detail="", points=0, fix=None):
        self.findings.append(Finding(check, severity, title, detail, points, fix))


@dataclass
class Report:
    domain: str
    score: int
    letter: str
    findings: list
    records: list              # list[Fix]
    guidance: list             # list[str]
    data: dict
    generated: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "letter": self.letter,
            "generated": self.generated,
            "version": self.version,
            "findings": [f.to_dict() for f in self.findings],
            "records_to_publish": [r.to_dict() for r in self.records],
            "cold_email_send_guidance": {
                "label": "GUIDANCE (rules of thumb, not a DNS finding)",
                "items": list(self.guidance),
            },
            "data": self.data,
        }
