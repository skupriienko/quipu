"""CLI and Stdio JSON-RPC 2.0 MCP server tests for `quipu`."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import quipu
from quipu.cli import main
from quipu.mcp_server import QUIPU_ACTIONS, QuipuMCPServer, serve_mcp_stdio


def test_cli_sample_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sample", "--format-version", "2.0"]) == 0
    v2_wire = capsys.readouterr().out
    assert "~= QUIPU/2.0" in v2_wire

    assert main(["sample", "--format-version", "1.0", "--json"]) == 0
    v1_payload = json.loads(capsys.readouterr().out)
    assert v1_payload["ast"]["version"] == "QUIPU/1.0"

    valid_file = tmp_path / "valid.quipu"
    valid_file.write_text(v2_wire, encoding="utf-8")
    assert main(["verify", "--file", str(valid_file), "--json"]) == 0
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["valid"] is True
    assert verify_out["verdict"] == "VERIFIED"

    bad_file = tmp_path / "bad.quipu"
    bad_file.write_text(v2_wire.replace("2026.11.25", "2099.01.01"), encoding="utf-8")
    assert main(["verify", "--file", str(bad_file), "--json"]) == 1
    bad_out = json.loads(capsys.readouterr().out)
    assert bad_out["valid"] is False


def test_cli_json_conversion_bench_micro_and_compat(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src_data = {
        "service": "billing",
        "items": [
            {"sku": "A1", "qty": 2},
            {"sku": "B2", "qty": 3},
        ],
    }
    json_file = tmp_path / "input.json"
    json_file.write_text(json.dumps(src_data), encoding="utf-8")

    assert main(["from-json", "--file", str(json_file), "--mode", "sealed"]) == 0
    quipu_wire = capsys.readouterr().out
    quipu_file = tmp_path / "encoded.quipu"
    quipu_file.write_text(quipu_wire, encoding="utf-8")

    assert main(["to-json", "--file", str(quipu_file)]) == 0
    assert json.loads(capsys.readouterr().out) == src_data

    assert main(["bench", "--file", str(json_file), "--json"]) == 0
    bench_out = json.loads(capsys.readouterr().out)
    assert bench_out["roundtrip_exact"] is True

    assert main(["micro", "--file", str(quipu_file), "--json"]) == 0
    micro_out = json.loads(capsys.readouterr().out)
    assert "Q^=" in micro_out["micro"]

    v1_file = tmp_path / "v1.quipu"
    v1_file.write_text(quipu.sample_quipu_v1(), encoding="utf-8")

    assert (
        main(
            [
                "upgrade",
                "--file",
                str(v1_file),
                "--admin-tier",
                "working",
                "--tag",
                "rel",
                "--json",
            ]
        )
        == 0
    )
    up_out = json.loads(capsys.readouterr().out)
    assert up_out["version"] == "QUIPU/2.0"

    v2_file = tmp_path / "v2.quipu"
    v2_file.write_text(up_out["quipu_text"], encoding="utf-8")

    assert main(["downgrade", "--file", str(v2_file), "--json"]) == 0
    down_out = json.loads(capsys.readouterr().out)
    assert down_out["version"] == "QUIPU/1.0"

    assert main(["distill", "--file", str(v2_file), "--json"]) == 0
    distill_out = json.loads(capsys.readouterr().out)
    assert distill_out["version"] == "QUIPU/2.0"
    assert "tier=summary" in distill_out["quipu_text"]


def test_cli_cwe22_containment_and_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["verify", "--file", "/etc/passwd"]) == 1
    captured = capsys.readouterr()
    assert "CWE-22 guard" in captured.err

    assert main(["verify", "--file", "/etc/passwd", "--json"]) == 1
    err_json = json.loads(capsys.readouterr().out)
    assert err_json["valid"] is False
    assert "CWE-22 guard" in err_json["error"]

    missing = tmp_path / "does_not_exist.quipu"
    assert main(["verify", "--file", str(missing)]) == 1
    assert "File not found" in capsys.readouterr().err

    assert main(["from-json"]) == 1
    assert "--file is required" in capsys.readouterr().err


def test_mcp_server_protocol_and_all_quipu_codec_actions() -> None:
    server = QuipuMCPServer()

    init_resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "quipu-mcp"

    ping_resp = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}

    list_resp = server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert list_resp is not None
    tools = list_resp["result"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "quipu_codec"
    assert set(tools[0]["inputSchema"]["properties"]["action"]["enum"]) == set(QUIPU_ACTIONS)

    assert server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def call(req_id: int, arguments: dict[str, object]) -> dict[str, object]:
        resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": "quipu_codec", "arguments": arguments},
            }
        )
        assert resp is not None
        assert resp["result"]["isError"] is False
        structured = resp["result"]["structuredContent"]
        assert isinstance(structured, dict)
        return structured

    sample_data = {"env": "prod", "rows": [{"k": "x", "v": 10}, {"k": "y", "v": 20}]}
    enc = call(10, {"action": "encode", "data": sample_data, "doc_id": "mcp.test"})
    quipu_text = str(enc["quipu_text"])
    assert "~= QUIPU/2.0" in quipu_text

    ver = call(11, {"action": "verify", "quipu_text": quipu_text})
    assert ver["valid"] is True

    dec = call(12, {"action": "decode", "quipu_text": quipu_text})
    assert dec["data"] == sample_data

    from_j = call(13, {"action": "from_json", "json_text": json.dumps(sample_data)})
    assert "~= QUIPU/2.0" in str(from_j["quipu_text"])

    to_j = call(14, {"action": "to_json", "quipu_text": quipu_text})
    assert json.loads(str(to_j["json_text"])) == sample_data

    micro = call(15, {"action": "micro", "quipu_text": quipu_text})
    assert "Q^=" in str(micro["micro"])

    bench = call(16, {"action": "benchmark", "data": sample_data})
    assert bench["roundtrip_exact"] is True

    v1_wire = quipu.sample_quipu_v1()
    up = call(17, {"action": "upgrade", "quipu_text": v1_wire, "admin_tier": "working"})
    assert up["version"] == "QUIPU/2.0"

    down = call(18, {"action": "downgrade", "quipu_text": str(up["quipu_text"])})
    assert down["version"] == "QUIPU/1.0"

    distilled = call(19, {"action": "distill", "quipu_text": quipu_text, "doc_id": "mcp.sum"})
    assert distilled["version"] == "QUIPU/2.0"
    assert "tier=summary" in str(distilled["quipu_text"])

    err_call = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {"name": "quipu_codec", "arguments": {"action": "decode"}},
        }
    )
    assert err_call is not None
    assert err_call["result"]["isError"] is True

    unknown_tool = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        }
    )
    assert unknown_tool is not None
    assert unknown_tool["error"]["code"] == -32602

    unknown_method = server.handle_request({"jsonrpc": "2.0", "id": 22, "method": "nope"})
    assert unknown_method is not None
    assert unknown_method["error"]["code"] == -32601


def test_serve_mcp_stdio_roundtrip() -> None:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = io.StringIO()
    assert serve_mcp_stdio(stdin=stdin, stdout=stdout) == 0

    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert [line["id"] for line in lines] == [1, 2]


def test_draw_python_cli_and_mcp(capsys: pytest.CaptureFixture[str]) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    telem_path = repo_root / "examples" / "telemetry_banded.quipu"
    ledger_path = repo_root / "examples" / "ledger_sealed.quipu"
    telem_wire = telem_path.read_text(encoding="utf-8")

    # 1. Python API (draw, draw_quipu, render_quipu_ascii)
    ascii_telem = quipu.draw(telem_wire)
    assert ascii_telem == quipu.draw_quipu(telem_wire)
    assert ascii_telem == quipu.render_quipu_ascii(quipu.parse(telem_wire))
    assert "PRIMARY CORD" in ascii_telem
    assert "(LOOP)" in ascii_telem and "(TASSEL)" in ascii_telem
    assert "▲" in ascii_telem
    assert "⟨1E⟩" in ascii_telem
    assert "⤵" not in ascii_telem and "⤴ *prod_defaults" in ascii_telem
    assert "band spacer" in ascii_telem

    # 2. CLI `quipu draw` plain & JSON modes across real example fixtures
    assert main(["draw", "--file", str(telem_path)]) == 0
    cli_telem = capsys.readouterr().out
    assert "PRIMARY CORD" in cli_telem
    assert "pipeline.telemetry.batch" in cli_telem

    assert main(["draw", "--file", str(ledger_path), "--json"]) == 0
    cli_ledger = json.loads(capsys.readouterr().out)
    assert "^net(credit, debt)=0" in cli_ledger["ascii"]
    assert "^quota(guard, pct=22.5)=4000" in cli_ledger["ascii"]

    # 3. Standalone MCP `draw` action
    mcp_res = QuipuMCPServer().call_tool({"action": "draw", "quipu_text": telem_wire})
    assert mcp_res["ascii"] == ascii_telem
