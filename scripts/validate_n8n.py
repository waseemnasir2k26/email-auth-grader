"""Validate n8n workflow JSON files. Usage: python scripts/validate_n8n.py [file ...]

Structural checks only (no n8n install needed): valid JSON, required keys, unique node
names/ids, connections reference real nodes, a trigger exists, nothing secret-looking, and
-- specific to this repo -- every Execute Command node is reachable only through a
node whose name starts with "Validate" (shell-injection guard).
"""
import glob
import json
import os
import re
import sys

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|"
                       r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\"apiKey\"\s*:\s*\"[^\"]{8,}\")")
TRIGGER_HINTS = ("trigger", "webhook", "executeWorkflowTrigger", "cron", "schedule")


def validate(doc: dict) -> list:
    errs = []
    nodes = doc.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return ["'nodes' must be a non-empty list"]
    if not isinstance(doc.get("connections"), dict):
        errs.append("'connections' must be an object")
    names, ids = set(), set()
    for n in nodes:
        for k in ("id", "name", "type", "typeVersion", "position", "parameters"):
            if k not in n:
                errs.append(f"node {n.get('name', '?')!r} missing {k!r}")
        if n.get("name") in names:
            errs.append(f"duplicate node name {n.get('name')!r}")
        if n.get("id") in ids:
            errs.append(f"duplicate node id {n.get('id')!r}")
        names.add(n.get("name"))
        ids.add(n.get("id"))
        if not str(n.get("type", "")).startswith(("n8n-nodes-base.", "@n8n/")):
            errs.append(f"node {n.get('name')!r} has unexpected type {n.get('type')!r}")
    edges = {}
    for src, outs in (doc.get("connections") or {}).items():
        if src not in names:
            errs.append(f"connection from unknown node {src!r}")
        for branch in outs.get("main", []):
            for link in branch:
                if link["node"] not in names:
                    errs.append(f"connection {src!r} -> unknown node {link['node']!r}")
                edges.setdefault(src, []).append(link["node"])
    if not any(any(h.lower() in n["type"].lower() for h in TRIGGER_HINTS) for n in nodes if "type" in n):
        errs.append("no trigger node found")
    if SECRET_RE.search(json.dumps(doc)):
        errs.append("secret-looking string found in workflow JSON")
    # every path to an Execute Command node must pass through a "Validate..." node
    triggers = [n["name"] for n in nodes if any(h.lower() in n["type"].lower() for h in TRIGGER_HINTS)]
    cmd_nodes = {n["name"] for n in nodes if n["type"].endswith("executeCommand")}

    def walk(name, guarded, seen):
        if name in cmd_nodes and not guarded:
            errs.append(f"Execute Command node {name!r} reachable without a 'Validate' node before it")
        if name in seen:
            return
        for nxt in edges.get(name, []):
            walk(nxt, guarded or nxt.lower().startswith("validate"), seen | {name})

    for t in triggers:
        walk(t, False, frozenset())
    return errs


def main(argv):
    files = argv or sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "n8n", "*.json")))
    if not files:
        print("no workflow files found")
        return 1
    bad = 0
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                errs = validate(json.load(fh))
        except (OSError, json.JSONDecodeError) as e:
            errs = [f"cannot load: {e}"]
        print(("FAIL " if errs else "OK   ") + os.path.relpath(f))
        for e in errs:
            print("   - " + e)
        bad += bool(errs)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
