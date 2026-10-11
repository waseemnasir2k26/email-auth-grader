"""Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0). No SDK dependency.

Implements initialize, ping, tools/list, tools/call and ignores notifications.
Tools: grade_domain, explain_record, suggest_dmarc_step, check_headers.
"""
from __future__ import annotations

import json
import sys

from . import __version__
from .checks.dmarc import find_dmarc, suggest_step
from .dnsio import DnsPythonResolver, clean_domain
from .explain import explain_record
from .headers import check_headers
from .score import grade_domain

SUPPORTED = ("2025-06-18", "2025-03-26", "2024-11-05")

TOOLS = [
    {"name": "grade_domain",
     "description": "Grade a domain's cold-email readiness from public DNS (SPF, DKIM, DMARC, MX, MTA-STS, "
                    "TLS-RPT, BIMI). Returns a 0-100 score, A-F letter, findings and exact DNS records to publish.",
     "inputSchema": {"type": "object", "required": ["domain"], "properties": {
         "domain": {"type": "string"},
         "selectors": {"type": "array", "items": {"type": "string"}, "description": "extra DKIM selectors to probe"},
         "check_http": {"type": "boolean", "description": "fetch the MTA-STS policy (default true)"}}}},
    {"name": "explain_record",
     "description": "Explain a pasted SPF, DKIM, DMARC, MTA-STS, TLS-RPT or BIMI TXT record in plain English.",
     "inputSchema": {"type": "object", "required": ["record"], "properties": {
         "record": {"type": "string"},
         "type": {"type": "string", "enum": ["spf", "dkim", "dmarc", "mta-sts", "tls-rpt", "bimi"]}}}},
    {"name": "suggest_dmarc_step",
     "description": "Given a domain's current DMARC record (or a domain to look it up), return the safe next step on "
                    "the none -> quarantine -> reject ladder with the exact record to publish.",
     "inputSchema": {"type": "object", "properties": {
         "domain": {"type": "string", "description": "look the record up in DNS"},
         "current_record": {"type": "string", "description": "paste the record instead; omit if none is published"}}}},
    {"name": "check_headers",
     "description": "Check a raw email message (RFC 822 text) for List-Unsubscribe / RFC 8058 one-click headers and "
                    "DKIM-Signature d= alignment with the From domain. Does not verify signatures cryptographically.",
     "inputSchema": {"type": "object", "required": ["eml_text"], "properties": {"eml_text": {"type": "string"}}}},
]


class ToolError(Exception):
    pass


def call_tool(name, args, resolver):
    if name == "grade_domain":
        r = grade_domain(args.get("domain", ""), resolver, args.get("selectors") or None,
                         args.get("check_http", True))
        return r.to_dict()
    if name == "explain_record":
        if not args.get("record"):
            raise ToolError("record is required")
        return explain_record(args["record"], args.get("type", ""))
    if name == "suggest_dmarc_step":
        if args.get("domain"):
            d = clean_domain(args["domain"])
            rec, where, _, _ = find_dmarc(d, resolver)
            return {"domain": d, "current_record": rec, **suggest_step(rec, d)}
        rec = args.get("current_record") or None
        return {"current_record": rec, **suggest_step(rec)}
    if name == "check_headers":
        if not args.get("eml_text"):
            raise ToolError("eml_text is required")
        return check_headers(args["eml_text"])
    raise ToolError(f"unknown tool: {name}")


def handle(msg, resolver):
    """Return a response dict, or None for notifications."""
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:  # notification (or malformed): never answer
        return None
    ok = lambda result: {"jsonrpc": "2.0", "id": mid, "result": result}  # noqa: E731
    err = lambda code, m: {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": m}}  # noqa: E731
    if method == "initialize":
        want = (msg.get("params") or {}).get("protocolVersion")
        return ok({"protocolVersion": want if want in SUPPORTED else SUPPORTED[0],
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "email-auth-grader", "version": __version__}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        p = msg.get("params") or {}
        try:
            out = call_tool(p.get("name"), p.get("arguments") or {}, resolver)
            return ok({"content": [{"type": "text", "text": json.dumps(out, indent=2)}], "isError": False})
        except (ToolError, ValueError) as e:
            return ok({"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
    return err(-32601, f"method not found: {method}")


def serve(resolver=None, stdin=None, stdout=None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    resolver = resolver or DnsPythonResolver()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            if not isinstance(msg, dict):
                resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
            else:
                resp = handle(msg, resolver)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    return 0
