# email-auth-grader

Cold email lands in spam and nobody tells you why. This grades a domain's email authentication from public DNS and prints the exact records to publish.

You get a 0-100 score, an A-F letter, a list of findings (worst first) and paste-ready DNS records. It reads public DNS only: no logins, no sending, no API keys. One runtime dependency (`dnspython`).

- **SPF**: one record only, recursive lookup count against the RFC 7208 limit of 10, void lookups, `+all` / `?all` / missing `all`.
- **DKIM**: probes 36 common selectors (or your own with `--selectors`), reports RSA key length, revoked keys and test mode.
- **DMARC**: policy, `pct`, `rua`, alignment, parent-domain inheritance, and a safe next step up the none, quarantine, reject ladder.
- **MX, MTA-STS, TLS-RPT, BIMI**: presence and sanity, including the MTA-STS policy fetch and MX matching.
- **Message headers** (`.eml`): `List-Unsubscribe`, RFC 8058 one-click, DKIM `d=` alignment with the From domain.
- **Outputs**: text, JSON, Markdown, print-ready HTML. Bulk CSV mode, a stdio MCP server and an n8n sub-workflow.

## Quickstart

Requires Python 3.10+. Not on PyPI yet, so install from GitHub:

```bash
pip install git+https://github.com/waseemnasir2k26/email-auth-grader
email-auth-grader grade yourdomain.com
email-auth-grader grade yourdomain.com --format html --out report.html
email-auth-grader bulk prospects.csv --out results.csv
email-auth-grader headers message.eml
email-auth-grader mcp
```

Try it with no network, using the recorded zones in `fixtures/`:

```bash
email-auth-grader grade no-dmarc.example --zone fixtures/no-dmarc.json
```

Sample reports (generated offline, reproducible) are in [`examples/`](examples): HTML, Markdown, JSON and text.

## Example output (excerpt)

```
GRADE C  (75/100)
  [HIGH] SPF needs 11 DNS lookups (limit 10)  (-20)
      Over the limit the result is permerror and SPF fails. Remove unused includes,
      move bulk senders to a subdomain, or flatten includes to ip4:/ip6: ranges.
```

That one is the synthetic `spf-overlimit.example` fixture.

## How the score works

Start at 100 and subtract points per finding. Any critical finding (for example SPF ending in `+all`) caps the score at 59. Letters: A 90+, B 80+, C 70+, D 60+, F below. The penalty for each finding is the last number passed to its `res.add(...)` call in `grader/checks/`.

## Bulk mode for agencies

Grade a prospect list before writing a single email. The CSV needs a `domain` column (or domains in the first column).

```bash
email-auth-grader bulk examples/prospects.csv --out examples/bulk-results.csv --zone fixtures/bulk-demo.json
```

Output is one row per domain: per-check status, grade, SPF lookups, DMARC policy and the top fix. It costs roughly 45 DNS queries per domain, so keep `--workers` modest.

## Use it from Claude (MCP)

```json
{
  "mcpServers": {
    "email-auth-grader": { "command": "email-auth-grader", "args": ["mcp"] }
  }
}
```

Tools: `grade_domain`, `explain_record`, `suggest_dmarc_step`, `check_headers`. Plain stdio JSON-RPC, no SDK dependency.

## Use it from n8n

Import [`n8n/email-auth-grader-subworkflow.json`](n8n/email-auth-grader-subworkflow.json). It validates the domain, runs the CLI and returns `score`, `letter`, `top_issue`, `records_to_publish` and `needs_help`. The CLI must be installed on the n8n host and the Execute Command node must be enabled on your instance. Check the file with `python scripts/validate_n8n.py`.

## For you if

You send cold or bulk email and want to know whether SPF, DKIM and DMARC are the reason it is not landing, or you are an agency that wants a concrete reason to start a conversation with a prospect.

## Limits

- A missing DKIM key is a hint, not proof: selectors cannot be listed from DNS. Read `s=` from a real message and pass `--selectors`.
- `headers` checks presence, covered headers and `d=` alignment. It does not verify the signature cryptographically.
- Relaxed alignment is approximated as "same last two labels" (no public-suffix list), so `co.uk`-style domains can be misjudged.
- `exists:` with macros is counted but not resolved.
- It cannot see sending reputation, rDNS or spam rate. The send-guidance block in each report is a rule of thumb, not a check.
- MX-based SPF suggestions cover a short table of well-known providers; confirm the include in your provider's docs.

## Develop

```bash
pip install -e ".[dev]"
pytest                          # no network needed
python scripts/validate_n8n.py
```

The GitHub Actions workflow is in [`ci/ci.yml`](ci/ci.yml); copy it to `.github/workflows/ci.yml` to enable it on a fork.

Related: [coldsend-lint](https://github.com/waseemnasir2k26/coldsend-lint) lints campaign copy and blocklists; this one covers the DNS and header side.

## Built by SkynetLabs

MIT licensed. Not legal advice.

Need this wired into your business? SkynetLabs builds voice agents, n8n back offices and sites that convert → https://skynetjoe.com
