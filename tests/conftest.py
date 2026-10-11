import datetime
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from grader.dnsio import ZoneResolver  # noqa: E402

NOW = datetime.datetime(2026, 10, 12, 9, 0, 0, tzinfo=datetime.timezone.utc)


def fixture_path(name):
    return os.path.join(ROOT, "fixtures", name + ".json")


@pytest.fixture
def zone():
    """FakeResolver factory: zone('perfect') loads a recorded fixture."""
    def _load(name):
        return ZoneResolver.from_json(fixture_path(name))
    return _load


@pytest.fixture
def now():
    return NOW


def titles(report):
    return [f.title for f in report.findings]


def has(report, check, severity=None, contains=""):
    return any(f.check == check and (severity is None or f.severity == severity) and contains.lower() in f.title.lower()
               for f in report.findings)
