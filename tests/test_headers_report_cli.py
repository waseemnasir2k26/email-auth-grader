import csv
import json
import os
import subprocess
import sys

import pytest

from conftest import ROOT, fixture_path
from grader.cli import main, read_domains
from grader.explain import detect_kind, explain_record
from grader.headers import aligned, check_headers
from grader.report import render
from grader.score import grade_domain

EML = os.path.join(ROOT, "tests", "eml")


def eml(name):
    with open(os.path.join(EML, name + ".eml"), "rb") as fh:
        return check_headers(fh.read())


def titles(r):
    return [f["title"] for f in r["findings"]]


def test_good_message_scores_100():
    r = eml("good")
    assert r["score"] == 100 and r["letter"] == "A"
    assert r["from_domain"] == "outreach.example"
    assert r["authentication_results"] == {"dkim": "pass", "spf": "pass", "dmarc": "pass"}


def test_missing_list_unsubscribe():
    assert any("No List-Unsubscribe" in t for t in titles(eml("no-unsub")))


def test_mailto_only_and_no_post():
    assert any("mailto-only" in t for t in titles(eml("mailto-only")))
    assert any("without List-Unsubscribe-Post" in t for t in titles(eml("no-post")))


def test_dkim_d_misalignment_is_high():
    r = eml("misaligned")
    f = [x for x in r["findings"] if "does not align" in x["title"]][0]
    assert f["severity"] == "high"
    assert r["score"] <= 80


def test_unsigned_message_and_unsigned_unsub_headers():
    assert any("No DKIM-Signature" in t for t in titles(eml("no-dkim")))
    assert any("does not sign the unsubscribe" in t for t in titles(eml("unsigned-unsub")))


def test_alignment_helper():
    assert aligned("mail.example.com", "example.com")
    assert not aligned("mail.example.com", "example.com", strict=True)
    assert not aligned("example.com", "other.com")


def test_unparseable_from():
    r = check_headers("Subject: x\n\nbody")
    assert any("From" in t for t in titles(r))


def test_html_golden(zone, now):
    r = grade_domain("perfect.example", zone("perfect"), now=now)
    with open(os.path.join(ROOT, "tests", "golden", "perfect.html"), encoding="utf-8") as fh:
        golden = fh.read()
    assert render(r, "html").rstrip() == golden.rstrip()


def test_html_escapes_and_has_footer(zone, now):
    r = grade_domain("dmarc-none.example", zone("dmarc-none"), now=now)
    h = render(r, "html")
    assert "Graded by" in h and "SkynetLabs" in h
    assert "Fix it for you: cold-email infrastructure setup" in h
    assert "fiverr.com/agencies/skynetjoellc" in h and "upwork.com/freelancers/muhammadwaseemnasir" in h
    assert "{{" not in h
    assert "@media print" in h


def test_all_formats_render(zone, now):
    r = grade_domain("no-dmarc.example", zone("no-dmarc"), now=now)
    assert render(r, "text").startswith("email-auth-grader")
    assert "| DMARC | FAIL |" in render(r, "md")
    j = json.loads(render(r, "json"))
    assert j["letter"] == r.letter and j["cold_email_send_guidance"]["items"]
    assert "GUIDANCE" in j["cold_email_send_guidance"]["label"]


def test_guidance_is_labelled_in_text(zone, now):
    t = render(grade_domain("perfect.example", zone("perfect"), now=now), "text")
    assert "not a DNS check" in t


def test_explain_record():
    assert detect_kind("v=spf1 -all") == "spf" and detect_kind("v=DMARC1; p=none") == "dmarc"
    assert detect_kind("hello") == "unknown"
    e = explain_record("v=spf1 include:a.example ip4:1.2.3.4 ~all")
    assert any("1 of the 10" in ln for ln in e["explanation"])
    assert any("softfail" in ln for ln in e["explanation"])
    assert explain_record("v=DMARC1; p=quarantine; pct=50")["tags"]["pct"] == "50"


def test_cli_grade_json_and_fail_under(capsys):
    assert main(["grade", "perfect.example", "--zone", fixture_path("perfect"), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["score"] == 100
    assert main(["grade", "no-dmarc.example", "--zone", fixture_path("no-dmarc"), "--fail-under", "95"]) == 1
    assert main(["grade", "not a domain", "--zone", fixture_path("perfect")]) == 2


def test_cli_bulk(tmp_path, capsys):
    src = tmp_path / "in.csv"
    src.write_text("company,domain\nA,perfect.example\nB,no-dmarc.example\nC,perfect.example\nD,bad domain\n")
    out = tmp_path / "out.csv"
    assert main(["bulk", str(src), "--out", str(out), "--zone", fixture_path("bulk-demo"), "--workers", "2"]) == 0
    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    assert [r["domain"] for r in rows] == ["perfect.example", "no-dmarc.example", "bad domain"]
    assert rows[0]["grade"] == "A" and rows[1]["dmarc"] == "FAIL"
    assert "No DMARC" in rows[1]["top_fix"]
    assert rows[2]["error"]


def test_read_domains_first_column_without_header(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("a.example\nb.example\n")
    assert read_domains(str(p)) == ["a.example", "b.example"]


def test_cli_headers(capsys):
    assert main(["headers", os.path.join(EML, "good.eml"), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["letter"] == "A"


def test_module_entrypoint_runs_offline():
    p = subprocess.run([sys.executable, "-m", "grader", "grade", "perfect.example", "--zone",
                        fixture_path("perfect"), "--format", "md"], capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0 and "Grade A (100/100)" in p.stdout
