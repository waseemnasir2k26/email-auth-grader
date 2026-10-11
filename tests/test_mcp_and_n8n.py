import io
import json
import os
import subprocess
import sys

from conftest import ROOT, fixture_path
from grader.dnsio import ZoneResolver
from grader.mcp_server import TOOLS, handle, serve

sys.path.insert(0, os.path.join(ROOT, "scripts"))
import validate_n8n  # noqa: E402


def rpc(method, params=None, id_=1):
    m = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        m["params"] = params
    return m


def call(name, args, resolver):
    resp = handle(rpc("tools/call", {"name": name, "arguments": args}), resolver)
    return resp["result"], json.loads(resp["result"]["content"][0]["text"]) if not resp["result"]["isError"] else None


def test_initialize_and_tools_list(zone):
    r = handle(rpc("initialize", {"protocolVersion": "2025-06-18"}), zone("perfect"))
    assert r["result"]["serverInfo"]["name"] == "email-auth-grader"
    assert r["result"]["protocolVersion"] == "2025-06-18"
    assert handle(rpc("initialize", {"protocolVersion": "1999-01-01"}), None)["result"]["protocolVersion"] == "2025-06-18"
    names = [t["name"] for t in handle(rpc("tools/list"), None)["result"]["tools"]]
    assert names == ["grade_domain", "explain_record", "suggest_dmarc_step", "check_headers"]
    assert all(t["inputSchema"]["type"] == "object" for t in TOOLS)


def test_notifications_get_no_response():
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, None) is None


def test_unknown_method_error():
    assert handle(rpc("nope"), None)["error"]["code"] == -32601


def test_grade_domain_tool(zone):
    res, data = call("grade_domain", {"domain": "no-dmarc.example"}, zone("no-dmarc"))
    assert res["isError"] is False
    assert data["domain"] == "no-dmarc.example" and data["records_to_publish"]


def test_grade_domain_bad_input_is_tool_error(zone):
    res, _ = call("grade_domain", {"domain": "???"}, zone("perfect"))
    assert res["isError"] is True


def test_explain_and_dmarc_step_tools(zone):
    _, e = call("explain_record", {"record": "v=spf1 mx -all"}, None)
    assert e["kind"] == "spf"
    _, s = call("suggest_dmarc_step", {"current_record": "v=DMARC1; p=none"}, None)
    assert s["step"] == "add_rua"
    _, s2 = call("suggest_dmarc_step", {"domain": "dmarc-none.example"}, zone("dmarc-none"))
    assert s2["current_record"] == "v=DMARC1; p=none"
    _, s3 = call("suggest_dmarc_step", {}, None)
    assert s3["step"] == "publish_monitoring"


def test_check_headers_tool():
    with open(os.path.join(ROOT, "tests", "eml", "misaligned.eml"), encoding="utf-8") as fh:
        _, d = call("check_headers", {"eml_text": fh.read()}, None)
    assert any("does not align" in f["title"] for f in d["findings"])
    res, _ = call("check_headers", {}, None)
    assert res["isError"]


def test_unknown_tool():
    res, _ = call("rm_rf", {}, None)
    assert res["isError"]


def test_serve_loop_handles_garbage_and_batches():
    inp = io.StringIO("\n".join([json.dumps(rpc("ping")), "{not json", "[1]", json.dumps(rpc("tools/list", id_=2))]) + "\n")
    out = io.StringIO()
    serve(ZoneResolver({}), inp, out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["result"] == {}
    assert lines[1]["error"]["code"] == -32700
    assert lines[2]["error"]["code"] == -32600
    assert len(lines[3]["result"]["tools"]) == 4


def test_stdio_subprocess_round_trip():
    msgs = [rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            rpc("tools/call", {"name": "grade_domain", "arguments": {"domain": "perfect.example"}}, id_=2)]
    p = subprocess.run([sys.executable, "-m", "grader", "mcp", "--zone", fixture_path("perfect")],
                       input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True,
                       cwd=ROOT, timeout=60)
    lines = [json.loads(x) for x in p.stdout.splitlines()]
    assert [x["id"] for x in lines] == [1, 2]
    assert json.loads(lines[1]["result"]["content"][0]["text"])["score"] == 100


def test_n8n_workflow_valid():
    path = os.path.join(ROOT, "n8n", "email-auth-grader-subworkflow.json")
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert validate_n8n.validate(doc) == []
    assert validate_n8n.main([path]) == 0


def test_n8n_validator_catches_problems():
    path = os.path.join(ROOT, "n8n", "email-auth-grader-subworkflow.json")
    doc = json.load(open(path, encoding="utf-8"))
    # unguarded Execute Command
    bad = json.loads(json.dumps(doc))
    bad["connections"]["When called by another workflow"]["main"][0][0]["node"] = "Run email-auth-grader"
    assert any("reachable without" in e for e in validate_n8n.validate(bad))
    # dangling connection
    bad2 = json.loads(json.dumps(doc))
    bad2["connections"]["Validate domain"]["main"][0][0]["node"] = "Ghost"
    assert any("unknown node" in e for e in validate_n8n.validate(bad2))
    # secret
    bad3 = json.loads(json.dumps(doc))
    bad3["nodes"][1]["parameters"]["jsCode"] += " ghp_" + "a" * 30
    assert any("secret" in e for e in validate_n8n.validate(bad3))
    # duplicate names
    bad4 = json.loads(json.dumps(doc))
    bad4["nodes"][1]["name"] = bad4["nodes"][0]["name"]
    assert any("duplicate" in e for e in validate_n8n.validate(bad4))
