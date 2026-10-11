"""Regenerate examples/ sample reports and the golden HTML used by tests (fixed timestamp, offline)."""
import datetime
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from grader.dnsio import ZoneResolver  # noqa: E402
from grader.report import render  # noqa: E402
from grader.score import grade_domain  # noqa: E402

NOW = datetime.datetime(2026, 10, 12, 9, 0, 0, tzinfo=datetime.timezone.utc)


def out(path, text):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def main():
    perfect = grade_domain("perfect.example", ZoneResolver.from_json(os.path.join(ROOT, "fixtures/perfect.json")), now=NOW)
    out("tests/golden/perfect.html", render(perfect, "html"))
    z = ZoneResolver.from_json(os.path.join(ROOT, "fixtures/dmarc-none.json"))
    r = grade_domain("dmarc-none.example", z, now=NOW)
    for fmt, ext in (("html", "html"), ("md", "md"), ("json", "json"), ("text", "txt")):
        out(f"examples/sample-report.{ext}", render(r, fmt))


if __name__ == "__main__":
    main()
