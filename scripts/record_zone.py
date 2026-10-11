"""Record a live domain's DNS answers into a --zone JSON file (public DNS only).

Usage: python scripts/record_zone.py example.com [out.json]
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from grader.dnsio import DnsPythonResolver, RecordingResolver  # noqa: E402
from grader.score import grade_domain  # noqa: E402


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    rec = RecordingResolver(DnsPythonResolver())
    r = grade_domain(argv[0], rec)
    out = argv[1] if len(argv) > 1 else f"{r.domain}.zone.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rec.dump(), fh, indent=2)
    print(f"recorded {len(rec.zone)} names for {r.domain} -> {out} (grade {r.letter} {r.score})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
