# Changelog

## 1.0.0 - 2026-10-12

First release.

- `grade`: SPF (recursive RFC 7208 lookup count, void lookups, qualifiers), DKIM (36 selectors, key length), DMARC (policy, pct, rua, alignment, parent inheritance, next-step ladder), MX and null MX, MTA-STS (TXT plus policy fetch), TLS-RPT, BIMI. Output as text, JSON, Markdown or print-ready HTML with a 0-100 score and A-F letter.
- Exact paste-in records: merged SPF, DMARC starter and next step, MTA-STS TXT plus policy file, TLS-RPT.
- `bulk`: grade a CSV of domains into a results CSV.
- `headers`: List-Unsubscribe and List-Unsubscribe-Post (RFC 8058) coverage, DKIM `d=` alignment.
- `mcp`: stdio MCP server with `grade_domain`, `explain_record`, `suggest_dmarc_step`, `check_headers` (no SDK dependency).
- n8n sub-workflow plus `scripts/validate_n8n.py`.
- Offline test suite on recorded zones; GitHub Actions CI on Python 3.10-3.13.
