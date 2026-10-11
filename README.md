# Email Auth Grader: SPF, DKIM, DMARC, MTA-STS and BIMI checker for cold email

**Gmail and Yahoo bulk-sender rules, checked in 2 seconds.** Grade any domain's cold-email readiness from public DNS and get a 0-100 score, an A-F letter, and the exact DNS records to paste in.

![Tests](https://img.shields.io/badge/tests-64%20passing-brightgreen.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![One dependency](https://img.shields.io/badge/dependencies-dnspython-lightgrey.svg)
![MCP server](https://img.shields.io/badge/MCP-stdio%20server-purple.svg)

Public DNS only. No logins, no sending, no scraping, no API keys. One runtime dependency (`dnspython`).

```
$ email-auth-grader grade yourdomain.com
```

## 60-second quickstart

```bash
pip install git+https://github.com/waseemnasir2k26/email-auth-grader
email-auth-grader grade yourdomain.com                    # terminal report
email-auth-grader grade yourdomain.com --format html --out report.html   # printable report
email-auth-grader bulk prospects.csv --out results.csv    # agencies: grade a whole list
email-auth-grader headers message.eml                     # List-Unsubscribe + DKIM d= alignment
email-auth-grader mcp                                     # stdio MCP server for Claude, Cursor, etc.
```

Requires Python 3.10+. Not on PyPI yet: install from GitHub as above, or `git clone` and `pip install -e .`. Try it with no network at all using the bundled recorded zones:

```bash
email-auth-grader grade no-dmarc.example --zone fixtures/no-dmarc.json
```

## Real output

This is a live run against the author's own domain, `skynetjoe.com` (about 2 seconds, public DNS, excerpt):

```
email-auth-grader 1.0.0  |  skynetjoe.com
GRADE B  (83/100)

CHECKS
  MX       PASS
  SPF      PASS
  DKIM     PASS
  DMARC    WARN
  MTA-STS  WARN
  TLS-RPT  WARN
  BIMI     INFO

FINDINGS (worst first)
  [MEDIUM] DMARC policy is p=none  (-12)
      Monitoring only: spoofed mail is not blocked. Fine as step one, but plan the move to quarantine and reject once reports are clean.
  [LOW] No MTA-STS record  (-3)
  [LOW] No TLS-RPT record  (-2)
  [INFO] Safe next DMARC step: p=quarantine; pct=10
      After 2-4 weeks of clean aggregate reports (all legitimate senders aligned), quarantine a small slice first.

PASSING
  [PASS] 2 MX record(s)
  [PASS] SPF ends in ~all (soft fail)
  [PASS] SPF uses 3/10 DNS lookups
  [PASS] DKIM key found: hostingermail-a

DNS RECORDS TO PASTE IN
  TXT  _smtp._tls.skynetjoe.com
      v=TLSRPTv1; rua=mailto:tls-reports@skynetjoe.com
```

A full sample, generated offline from a recorded zone so you can reproduce it byte for byte, lives in [`examples/`](examples): [`sample-report.html`](examples/sample-report.html) (print-ready), [`.md`](examples/sample-report.md), [`.json`](examples/sample-report.json) and [`.txt`](examples/sample-report.txt).

### What a failing domain looks like

`spf-overlimit.example` (a synthetic zone with 11 nested SPF lookups):

```
GRADE C  (75/100)
  [HIGH] SPF needs 11 DNS lookups (limit 10)  (-20)
      RFC 7208 section 4.6.4 caps include/a/mx/ptr/exists/redirect at 10 per check. Over the limit the
      result is permerror and SPF fails. Remove unused includes, move bulk senders to a subdomain, or
      flatten includes to ip4:/ip6: ranges (and re-flatten when vendors change them).
```

### Message headers

```
$ email-auth-grader headers tests/eml/misaligned.eml
Grade: B (80/100)
[HIGH] DKIM d= (esp-mailer.example) does not align with From (outreach.example)
       DMARC can only pass through DKIM when the signing domain (d=) matches the From domain. ...
[PASS] RFC 8058 one-click unsubscribe headers present
```

## Features

| Area                 | What it checks                                                                                                                                                                                                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **SPF**              | Present, exactly one record, recursive DNS-lookup count against the RFC 7208 limit of 10 (follows `include:` and `redirect=`, loop-safe), void lookups (limit 2), `+all` / `?all` / missing `all`, `ptr`. Emits a merged single record when you have several.                              |
| **DKIM**             | Probes 36 common selectors (Google, Microsoft 365 `selector1/2`, `k1`, `s1/s2`, Mandrill, Mailjet, Zoho, SES, SendGrid, Proton, Fastmail, Hostinger, HubSpot ...) or your own via `--selectors`. Reads the public key and reports RSA key length (flags 1024-bit), revoked keys and `t=y`. |
| **DMARC**            | Present, single, valid `p=`, `pct`, `rua`, alignment modes, inheritance from a parent domain, and a safe next step on the none, quarantine, reject ladder with the exact record to publish.                                                                                                |
| **MX**               | Present, null MX (RFC 7505), mailbox-provider detection (used to suggest the right SPF include).                                                                                                                                                                                           |
| **MTA-STS**          | TXT record, HTTPS policy fetch (no redirects, per RFC 8461), mode, `max_age`, and policy `mx:` patterns vs your real MX hosts. `--no-http` skips the fetch.                                                                                                                                |
| **TLS-RPT**          | Record present with `rua`.                                                                                                                                                                                                                                                                 |
| **BIMI**             | Record present, `l=` is https, and DMARC is actually enforcing at `pct=100`.                                                                                                                                                                                                               |
| **Headers** (`.eml`) | `List-Unsubscribe`, `List-Unsubscribe-Post` per RFC 8058 (https URL, exact `One-Click` value, covered by the DKIM `h=` list), `DKIM-Signature` `d=` alignment with the From domain, `rsa-sha1`, receiver `Authentication-Results`.                                                         |
| **Output**           | `text`, `json`, `md`, `html` (print CSS). 0-100 grade, A-F letter, findings, exact DNS records.                                                                                                                                                                                            |
| **Bulk**             | `bulk domains.csv --out results.csv`: one row per domain with per-check status, grade, SPF lookups, DMARC policy and the top fix.                                                                                                                                                          |
| **MCP**              | Stdio server, no SDK dependency: `grade_domain`, `explain_record`, `suggest_dmarc_step`, `check_headers`.                                                                                                                                                                                  |
| **n8n**              | Importable sub-workflow with a domain validator in front of the shell node.                                                                                                                                                                                                                |

### How the score works

Start at 100, subtract points per finding. Any critical finding (for example SPF ending in `+all`) caps the score at 59. Letters: A 90+, B 80+, C 70+, D 60+, F below.

| Finding                                                  | Points              |
| -------------------------------------------------------- | ------------------- |
| No SPF / no DMARC                                        | -25 each            |
| `+all`                                                   | -30 and capped to F |
| More than 10 SPF lookups, or several SPF records         | -20                 |
| DMARC `p=none`                                           | -12                 |
| `?all`                                                   | -12                 |
| No DKIM found on probed selectors / 1024-bit key / no MX | -10 each            |
| MTA-STS policy mismatching MX (enforce mode)             | -15                 |
| No `rua`, `pct<100`, no MTA-STS, no TLS-RPT              | -5 to -2            |

The full table is in the code (`grader/checks/`): each finding's penalty is the last number passed to its `res.add(...)` call.

## Cold-email send guidance (guidance, not a check)

Every report ends with a block clearly labelled as guidance: send from a separate subdomain, ramp volume up over several weeks, watch Google Postmaster Tools (Google's published guidance is to keep the user-reported spam rate under 0.30%, ideally under 0.10%), and keep an opt-out on every campaign. These are rules of thumb. The tool cannot see your sending reputation, rDNS, outbound TLS or spam rate.

## Bulk-prospect mode for agencies

Grade a prospect list before you write a single email. Each failing grade is a concrete reason to talk.

```bash
$ cat examples/prospects.csv
domain
perfect.example
no-dmarc.example
dmarc-none.example

$ email-auth-grader bulk examples/prospects.csv --out examples/bulk-results.csv --zone fixtures/bulk-demo.json
graded 3/3 domains -> examples/bulk-results.csv
  A: 1
  C: 2
```

`bulk-results.csv`:

| domain             | grade | score | spf  | dkim | dmarc | spf_lookups | dmarc_policy   | top_fix                |
| ------------------ | ----- | ----- | ---- | ---- | ----- | ----------- | -------------- | ---------------------- |
| perfect.example    | A     | 100   | PASS | PASS | PASS  | 1           | reject         |                        |
| no-dmarc.example   | C     | 70    | PASS | PASS | FAIL  | 1           | none-published | No DMARC record        |
| dmarc-none.example | C     | 78    | PASS | PASS | WARN  | 1           | none           | DMARC policy is p=none |

(The example domains are synthetic and use the reserved `.example` TLD.) The CSV needs a `domain` column or the domains in the first column. It only reads public DNS, roughly 45 DNS queries per domain; keep `--workers` modest and respect the people you contact.

## Use it from Claude (MCP)

```json
{
  "mcpServers": {
    "email-auth-grader": { "command": "email-auth-grader", "args": ["mcp"] }
  }
}
```

| Tool                 | Does                                                                                    |
| -------------------- | --------------------------------------------------------------------------------------- |
| `grade_domain`       | Full grade for a domain, with findings and records to publish                           |
| `explain_record`     | Plain-English explanation of a pasted SPF, DKIM, DMARC, MTA-STS, TLS-RPT or BIMI record |
| `suggest_dmarc_step` | Safe next DMARC step (by domain or pasted record) with the exact new record             |
| `check_headers`      | Raw message text in, List-Unsubscribe and DKIM alignment findings out                   |

The server speaks newline-delimited JSON-RPC 2.0 over stdio (MCP protocol versions 2025-06-18, 2025-03-26, 2024-11-05) and is covered by round-trip tests.

## Use it from n8n

Import [`n8n/email-auth-grader-subworkflow.json`](n8n/email-auth-grader-subworkflow.json). It takes a `domain` input, validates it (the Execute Command node runs in a shell, so untrusted input must be checked first), runs `email-auth-grader grade <domain> --format json`, and returns `score`, `letter`, `top_issue`, `records_to_publish` and a `needs_help` flag. It needs the CLI installed on the n8n host, and Execute Command can be disabled by default on newer n8n versions; enable it deliberately on a self-hosted instance. Check the file with `python scripts/validate_n8n.py`.

## FAQ

**Does it send email or touch my mailboxes?** No. It reads public DNS records (and, for MTA-STS, one public HTTPS policy file).

**It says no DKIM key found, but we sign mail.** DKIM selectors cannot be listed from DNS, so a miss is a hint, never proof. Read `s=` from a real message's `DKIM-Signature` and run `--selectors thatname`, or save the message and run `email-auth-grader headers message.eml`.

**Does `headers` verify the DKIM signature?** No. It checks presence, which headers the signature covers, and alignment of `d=` with the From domain. It does not do cryptographic verification.

**How exact is the alignment check?** Relaxed alignment is approximated as "same last two labels" because no public-suffix list is shipped, so multi-part TLDs such as `co.uk` can be misjudged.

**How exact is the SPF lookup count?** It follows `include:` and `redirect=` recursively and counts `a`, `mx`, `ptr`, `exists`, `include` and `redirect` as RFC 7208 does. `exists:` with macros is counted but not resolved, and an `mx` mechanism counts as one lookup.

**Does the paste-in DKIM record exist?** No, and we do not invent one: the key comes from your sending platform. For DKIM the report tells you what to do instead.

**What do the MX-based SPF suggestions assume?** A short table of well-known providers (Google Workspace, Microsoft 365, Zoho, Proton, Fastmail, iCloud). Confirm the include with your provider's docs before publishing.

**How is this different from coldsend-lint?** [coldsend-lint](https://github.com/waseemnasir2k26/coldsend-lint) lints a campaign: copy compliance (CAN-SPAM, GDPR, PECR, LSSI-CE, CASL) plus PTR and DNSBL checks. Email Auth Grader goes deeper on the authentication layer: recursive SPF lookup counting, key-length probing across selectors, MTA-STS policy fetch and MX matching, TLS-RPT, BIMI, RFC 8058 header checks, ready-to-paste records, an HTML report, bulk CSV mode, an MCP server and an n8n sub-workflow. Use both: this one for DNS and headers, coldsend-lint for copy and blocklists.

**Can I test without network?** Yes: `--zone fixtures/<name>.json` reads recorded answers. CI uses only these; there is no live DNS in the test suite. Record your own with `python scripts/record_zone.py yourdomain.com`.

## Develop

```bash
pip install -e ".[dev]"
pytest                                  # no network needed
python scripts/validate_n8n.py
python scripts/make_fixtures.py         # regenerate synthetic zones (needs openssl)
python scripts/make_examples.py         # regenerate examples/ and the golden HTML
```

The GitHub Actions workflow (Python 3.10-3.13, tests, n8n validation, CLI smoke test) is in [`ci/ci.yml`](ci/ci.yml); copy it to `.github/workflows/ci.yml` to enable it on a fork.

Layout: `grader/cli.py`, `grader/dnsio.py` (injectable resolver), `grader/checks/*.py`, `grader/score.py`, `grader/headers.py`, `grader/mcp_server.py`, `templates/report.html`.

## More from SkynetLabs

- [coldsend-lint](https://github.com/waseemnasir2k26/coldsend-lint): pre-send campaign lint for deliverability and copy compliance.
- [n8n-workflows](https://github.com/waseemnasir2k26/n8n-workflows): production n8n workflows from real client builds.
- [mcp-spend-guard](https://github.com/waseemnasir2k26/mcp-spend-guard): spend caps, rate limits and a kill switch for any MCP server.

## Work with SkynetLabs

Built by [Waseem Nasir](https://www.skynetjoe.com/?utm_source=github&utm_medium=readme&utm_campaign=email-auth-grader) at SkynetLabs — n8n + AI automation for small businesses.

- Hire on Fiverr: https://www.fiverr.com/agencies/skynetjoellc
- Hire on Upwork: https://www.upwork.com/freelancers/muhammadwaseemnasir
- Book a free call: https://calendly.com/skynetlabs/schedule-a-free-consultation

**Fix it for you: cold-email infrastructure setup** via [Fiverr](https://www.fiverr.com/agencies/skynetjoellc) or [Upwork](https://www.upwork.com/freelancers/muhammadwaseemnasir).

MIT licensed. Not legal advice.
