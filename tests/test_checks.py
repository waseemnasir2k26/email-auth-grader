from conftest import has, titles
from grader.checks.dkim import SELECTORS, parse_dkim, rsa_bits
from grader.checks.dmarc import suggest_step
from grader.checks.mtasts import mx_matches, parse_policy
from grader.checks.spf import check_spf, merge_spf
from grader.dnsio import ZoneResolver, clean_domain
from grader.score import grade_domain, letter_for, total
from grader.models import Finding

import pytest


def test_perfect_domain_scores_100(zone, now):
    r = grade_domain("perfect.example", zone("perfect"), now=now)
    assert r.score == 100
    assert r.letter == "A"
    assert r.records == []
    assert has(r, "dmarc", "pass", "reject")
    assert has(r, "mta-sts", "pass", "enforce")


def test_spf_over_ten_lookups(zone, now):
    r = grade_domain("spf-overlimit.example", zone("spf-overlimit"), now=now)
    assert r.data["spf"]["lookups"] == 11
    assert has(r, "spf", "high", "11 DNS lookups")
    assert r.score <= 80


def test_spf_counts_nested_includes_exactly(zone):
    res = check_spf("perfect.example", zone("perfect"))
    assert res.data["lookups"] == 1
    assert res.data["all"] == "-"


def test_missing_dmarc_is_high_and_gives_starter_record(zone, now):
    r = grade_domain("no-dmarc.example", zone("no-dmarc"), now=now)
    assert has(r, "dmarc", "high", "No DMARC")
    rec = [x for x in r.records if x.name == "_dmarc.no-dmarc.example"][0]
    assert rec.value.startswith("v=DMARC1; p=none; rua=mailto:dmarc-reports@no-dmarc.example")
    assert r.score <= 75


def test_dmarc_none_without_rua(zone, now):
    r = grade_domain("dmarc-none.example", zone("dmarc-none"), now=now)
    assert has(r, "dmarc", "medium", "p=none")
    assert has(r, "dmarc", "low", "no rua")
    fix = [x for x in r.records if x.name.startswith("_dmarc.")][0]
    assert "p=none" in fix.value and "rua=mailto:" in fix.value
    assert r.letter in ("C", "D")


def test_dkim_1024_flagged_and_2048_clean(zone, now):
    weak = grade_domain("dkim-1024.example", zone("dkim-1024"), now=now)
    assert weak.data["dkim"]["found"][0]["bits"] == 1024
    assert has(weak, "dkim", "medium", "1024-bit")
    good = grade_domain("perfect.example", zone("perfect"), now=now)
    assert good.data["dkim"]["found"][0]["bits"] == 2048
    assert not has(good, "dkim", "medium")


def test_mtasts_mismatch_detected(zone, now):
    r = grade_domain("mtasts-mismatch.example", zone("mtasts-mismatch"), now=now)
    assert has(r, "mta-sts", "high", "does not match")
    fix = [x for x in r.records if x.type == "FILE"][0]
    assert "mx: aspmx.l.google.com" in fix.value


def test_mtasts_policy_unreachable_and_no_http(zone, now):
    z = zone("mtasts-mismatch")
    z.https = {}
    assert has(grade_domain("mtasts-mismatch.example", z, now=now), "mta-sts", "medium", "not reachable")
    skipped = grade_domain("mtasts-mismatch.example", zone("mtasts-mismatch"), check_http=False, now=now)
    assert has(skipped, "mta-sts", "info", "skipped")


def test_nxdomain_is_zero(now):
    r = grade_domain("ghost.example", ZoneResolver({}), now=now)
    assert (r.score, r.letter) == (0, "F")
    assert has(r, "dns", "critical", "NXDOMAIN")


def _spf_zone(spf, extra=None):
    z = {"t.example": {"TXT": [spf] if isinstance(spf, str) else spf, "MX": ["10 mx.t.example"]}}
    z.update(extra or {})
    return ZoneResolver(z)


def test_spf_plus_all_is_critical_and_caps_grade(now):
    r = grade_domain("t.example", _spf_zone("v=spf1 +all"), now=now)
    assert has(r, "spf", "critical", "+all")
    assert r.score <= 59 and r.letter == "F"


def test_spf_question_all_and_missing_all():
    assert has(check_spf("t.example", _spf_zone("v=spf1 ip4:192.0.2.1 ?all")), "spf", "medium", "?all")
    res = check_spf("t.example", _spf_zone("v=spf1 ip4:192.0.2.1"))
    assert any("no 'all'" in f.title for f in res.findings)


def test_spf_multiple_records_merged_fix():
    res = check_spf("t.example", _spf_zone(["v=spf1 include:a.example -all", "v=spf1 include:b.example ~all"]))
    f = [x for x in res.findings if "SPF records" in x.title][0]
    assert f.fix.value == "v=spf1 include:a.example include:b.example ~all"


def test_spf_missing_uses_provider_include():
    z = ZoneResolver({"t.example": {"MX": ["1 aspmx.l.google.com"], "TXT": ["hello"]}})
    from grader.checks.mx import check_mx
    mx = check_mx("t.example", z)
    res = check_spf("t.example", z, mx.data)
    assert mx.data["provider"] == "Google Workspace"
    assert res.findings[0].fix.value == "v=spf1 include:_spf.google.com ~all"


def test_spf_void_lookups_and_ptr():
    spf = "v=spf1 a:gone1.example a:gone2.example a:gone3.example ptr -all"
    res = check_spf("t.example", _spf_zone(spf))
    assert res.data["void_lookups"] == 3
    assert any("void" in f.title for f in res.findings)
    assert any("ptr" in f.title for f in res.findings)


def test_spf_include_loop_does_not_hang():
    z = _spf_zone("v=spf1 include:loop.example -all",
                  {"loop.example": {"TXT": ["v=spf1 include:loop.example -all"]}})
    res = check_spf("t.example", z)
    assert res.data["lookups"] <= 3
    assert any("loop" in e for e in res.data["errors"])


def test_spf_redirect_followed():
    z = _spf_zone("v=spf1 redirect=_spf.t.example", {"_spf.t.example": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]}})
    res = check_spf("t.example", z)
    assert res.data["lookups"] == 1 and res.data["all"] == "-"


def test_merge_spf_dedupes_and_swaps_all():
    out = merge_spf(["v=spf1 include:a.x -all", "v=spf1 include:a.x ip4:1.2.3.4 +all"], ["include:b.x"], "~")
    assert out == "v=spf1 include:a.x ip4:1.2.3.4 include:b.x ~all"


def test_dkim_selector_list_and_custom_selectors(zone, now):
    assert len(SELECTORS) >= 25 and len(set(SELECTORS)) == len(SELECTORS)
    for s in ("google", "selector1", "k1", "s1", "mandrill", "mailjet", "zoho", "amazonses", "sendgrid"):
        assert s in SELECTORS
    r = grade_domain("perfect.example", zone("perfect"), selectors=["nope"], now=now)
    assert has(r, "dkim", "medium", "No DKIM key found on 1 probed")


def test_parse_dkim_variants():
    assert parse_dkim("v=DKIM1; k=rsa; p=")["revoked"] is True
    assert parse_dkim("v=DKIM1; k=ed25519; p=" + "A" * 43 + "=")["bits"] == 256
    assert parse_dkim("v=DKIM1; t=y; p=AAAA")["testing"] is True
    assert rsa_bits("not-base64!!") is None


def test_dmarc_subdomain_inherits_parent(zone, now):
    z = zone("perfect")
    z.zone["send.perfect.example"] = {"TXT": ["v=spf1 -all"], "MX": ["10 aspmx.l.google.com"]}
    r = grade_domain("send.perfect.example", z, now=now)
    assert r.data["dmarc"]["found_at"] == "perfect.example"
    assert has(r, "dmarc", "pass", "reject")


def test_dmarc_ladder():
    steps = [suggest_step(r, "x.com")["step"] for r in (
        None, "v=DMARC1; p=none", "v=DMARC1; p=none; rua=mailto:a@x.com",
        "v=DMARC1; p=quarantine; pct=10; rua=mailto:a@x.com", "v=DMARC1; p=quarantine; rua=mailto:a@x.com",
        "v=DMARC1; p=reject; pct=25", "v=DMARC1; p=reject", "v=DMARC1; rua=mailto:a@x.com")]
    assert steps == ["publish_monitoring", "add_rua", "to_quarantine_10", "raise_pct_25",
                     "to_reject_25", "reject_full", "done", "fix_syntax"]


def test_mx_missing_and_null_mx(now):
    r = grade_domain("t.example", ZoneResolver({"t.example": {"TXT": ["v=spf1 -all"]}}), now=now)
    assert has(r, "mx", "medium", "No MX")
    r2 = grade_domain("t.example", ZoneResolver({"t.example": {"TXT": ["v=spf1 -all"], "MX": ["0 ."]}}), now=now)
    assert has(r2, "mx", "info", "Null MX")


def test_mta_sts_helpers():
    assert mx_matches("*.example.com", "mx1.example.com")
    assert not mx_matches("*.example.com", "a.b.example.com")
    assert parse_policy("version: STSv1\nmode: enforce\nmx: A.example\n")["mx"] == ["a.example"]


def test_bimi_without_enforcement_flagged(zone, now):
    z = zone("dmarc-none")
    z.zone["default._bimi.dmarc-none.example"] = {"TXT": ["v=BIMI1; l=https://x.example/l.svg"]}
    assert has(grade_domain("dmarc-none.example", z, now=now), "bimi", "low", "not enforcing")


def test_scoring_helpers():
    assert [letter_for(s) for s in (100, 90, 89, 80, 70, 60, 59, 0)] == list("AABBCDFF")
    assert total([Finding("x", "high", "t", points=30), Finding("x", "low", "t", points=5)]) == 65
    assert total([Finding("x", "critical", "t", points=1)]) == 59
    assert total([Finding("x", "high", "t", points=500)]) == 0


@pytest.mark.parametrize("raw,expected", [("Example.COM", "example.com"), ("https://example.com/path", "example.com"),
                                          ("me@example.com", "example.com"), ("bücher.de", "xn--bcher-kva.de")])
def test_clean_domain(raw, expected):
    assert clean_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "nodot", "a b.com", "-x.com", "x.c"])
def test_clean_domain_rejects(bad):
    with pytest.raises(ValueError):
        clean_domain(bad)


def test_dns_error_does_not_crash(now):
    z = ZoneResolver({"t.example": {"TXT": ["v=spf1 -all"]}}, errors=["_dmarc.t.example"])
    r = grade_domain("t.example", z, now=now)
    assert has(r, "dmarc", "info", "lookup failed")
