"""Render a Report as text, markdown, JSON or HTML."""
from __future__ import annotations

import html
import json
import os

from .models import Report
from .score import sorted_findings

CHECK_ORDER = [("mx", "MX"), ("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC"),
               ("mta-sts", "MTA-STS"), ("tls-rpt", "TLS-RPT"), ("bimi", "BIMI")]
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "pass": "PASS"}
FOOTER_URL = "https://www.skynetjoe.com/?utm_source=github&utm_medium=report&utm_campaign=email-auth-grader"
FIVERR = "https://www.fiverr.com/agencies/skynetjoellc"
UPWORK = "https://www.upwork.com/freelancers/muhammadwaseemnasir"
CTA = "Fix it for you: cold-email infrastructure setup"


def check_status(report: Report, check: str) -> str:
    fs = [f for f in report.findings if f.check == check]
    if not fs:
        return "n/a"
    sev = {f.severity for f in fs}
    if sev & {"critical", "high"}:
        return "FAIL"
    if sev & {"medium", "low"}:
        return "WARN"
    return "PASS" if "pass" in sev else "INFO"


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_text(report: Report) -> str:
    o = [f"email-auth-grader {report.version}  |  {report.domain}",
         f"GRADE {report.letter}  ({report.score}/100)", "", "CHECKS"]
    for key, label in CHECK_ORDER:
        o.append(f"  {label:<8} {check_status(report, key)}")
    o += ["", "FINDINGS (worst first)"]
    shown = [f for f in sorted_findings(report.findings) if f.severity != "pass"]
    if not shown:
        o.append("  none")
    for f in shown:
        o.append(f"  [{SEV_LABEL[f.severity]}] {f.title}" + (f"  (-{f.points})" if f.points else ""))
        if f.detail:
            o.append(f"      {f.detail}")
    passes = [f for f in report.findings if f.severity == "pass"]
    if passes:
        o += ["", "PASSING"] + [f"  [PASS] {f.title}" for f in passes]
    if report.records:
        o += ["", "DNS RECORDS TO PASTE IN"]
        for r in report.records:
            o.append(f"  {r.type}  {r.name}")
            for ln in r.value.splitlines():
                o.append(f"      {ln}")
            if r.note:
                for ln in r.note.splitlines():
                    o.append(f"      # {ln}")
    o += ["", "COLD-EMAIL SEND GUIDANCE (guidance and rules of thumb, not a DNS check)"]
    o += [f"  - {g}" for g in report.guidance]
    o += ["", f"Generated {report.generated}. Graded by SkynetLabs. {CTA}: {FIVERR}"]
    return "\n".join(o)


def render_md(report: Report) -> str:
    o = [f"# Email authentication report: {report.domain}", "",
         f"**Grade {report.letter} ({report.score}/100)** - generated {report.generated}", "",
         "| Check | Status |", "|---|---|"]
    o += [f"| {label} | {check_status(report, key)} |" for key, label in CHECK_ORDER]
    o += ["", "## Findings"]
    shown = [f for f in sorted_findings(report.findings) if f.severity != "pass"]
    o += [f"- **{SEV_LABEL[f.severity]}** {f.title}" + (f" (-{f.points})" if f.points else "")
          + (f"\n  - {f.detail}" if f.detail else "") for f in shown] or ["- none"]
    if report.records:
        o += ["", "## DNS records to paste in"]
        for r in report.records:
            o += ["", f"`{r.type}` `{r.name}`", "", "```", r.value, "```"]
            if r.note:
                o.append(f"_{r.note}_")
    o += ["", "## Cold-email send guidance", "_Guidance and rules of thumb, not a DNS check._", ""]
    o += [f"- {g}" for g in report.guidance]
    o += ["", "---", f"Graded by [SkynetLabs]({FOOTER_URL}) - [{CTA}]({FIVERR})"]
    return "\n".join(o)


def _template() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "templates", "report.html"),
              os.path.join(here, "..", "templates", "report.html")):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return fh.read()
    raise FileNotFoundError("templates/report.html not found")


def render_html(report: Report) -> str:
    e = html.escape
    rows = "\n".join(
        f'<tr><td>{label}</td><td><span class="pill {check_status(report, key).lower()}">'
        f"{check_status(report, key)}</span></td></tr>" for key, label in CHECK_ORDER)
    fl = []
    for f in sorted_findings(report.findings):
        if f.severity == "pass":
            continue
        pts = f" <span class='pts'>-{f.points}</span>" if f.points else ""
        d = f"<p>{e(f.detail)}</p>" if f.detail else ""
        fl.append(f'<li class="sev-{f.severity}"><b>{SEV_LABEL[f.severity]}</b> {e(f.title)}{pts}{d}</li>')
    findings = "\n".join(fl) or "<li class='sev-pass'>No findings. Nothing to fix.</li>"
    rl = []
    for r in report.records:
        note = f"<p class='note'>{e(r.note)}</p>" if r.note else ""
        rl.append(f"<div class='rec'><div class='rt'>{e(r.type)} &middot; {e(r.name)}</div>"
                  f"<pre>{e(r.value)}</pre>{note}</div>")
    records = "\n".join(rl) or "<p>No records to change.</p>"
    guidance = "\n".join(f"<li>{e(g)}</li>" for g in report.guidance) or "<li>-</li>"
    subs = {
        "DOMAIN": e(report.domain), "SCORE": str(report.score), "LETTER": report.letter,
        "LETTER_CLASS": "grade-" + report.letter.lower(), "GENERATED": e(report.generated),
        "VERSION": e(report.version), "CHECK_ROWS": rows, "FINDINGS": findings, "RECORDS": records,
        "GUIDANCE": guidance, "FOOTER_URL": e(FOOTER_URL), "FIVERR": FIVERR, "UPWORK": UPWORK, "CTA": e(CTA),
    }
    out = _template()
    for k, v in subs.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def render(report: Report, fmt: str) -> str:
    return {"text": render_text, "md": render_md, "json": to_json, "html": render_html}[fmt](report)
