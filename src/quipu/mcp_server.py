"""quipu.mcp_server — Zero-Dependency Stdio JSON-RPC 2.0 MCP Server.

Exposes the `quipu_codec` tool over newline-delimited JSON-RPC 2.0 on stdio,
supporting `initialize`, `ping`, `tools/list`, and `tools/call`.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import IO, Any

from .ast_nodes import DEFAULT_QUIPU_VERSION, QuipuError, normalize_quipu_version
from .codec import (
    dump_quipu,
    dumps_quipu,
    loads_quipu,
    parse_quipu,
    quipu_to_json,
    render_quipu_ascii,
    render_quipu_micro,
    sample_quipu,
)
from .compat import (
    distill_working_to_summary,
    downgrade_quipu_to_v1,
    upgrade_quipu_to_v2,
)
from .verifier import benchmark_quipu_vs_json, verify_quipu

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "quipu-mcp"
SERVER_VERSION = "2.0.0"

QUIPU_ACTIONS: tuple[str, ...] = (
    "verify",
    "encode",
    "decode",
    "from_json",
    "to_json",
    "micro",
    "draw",
    "benchmark",
    "upgrade",
    "downgrade",
    "distill",
)

QUIPU_TOOL_SPEC: dict[str, Any] = {
    "name": "quipu_codec",
    "description": (
        "Encode, decode, verify (7-law QUIPU/1.0 and 10-law QUIPU/2.0), benchmark, "
        "compact, and convert between JSON and .quipu format."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": list(QUIPU_ACTIONS),
                "description": "Operation to run on the QUIPU codec or verifier.",
            },
            "quipu_text": {
                "type": "string",
                "description": "Input .quipu wire text.",
            },
            "json_text": {
                "type": "string",
                "description": "Input JSON string for from_json or benchmark.",
            },
            "data": {
                "description": "Arbitrary JSON-compatible Python data for encode or benchmark.",
            },
            "doc_id": {
                "type": "string",
                "default": "root",
                "description": "Document identifier for encode, from_json, or distill.",
            },
            "mode": {
                "type": "string",
                "enum": ["sealed", "lax"],
                "default": "sealed",
                "description": "Serialization seal mode.",
            },
            "version": {
                "type": "string",
                "enum": ["1.0", "2.0", "QUIPU/1.0", "QUIPU/2.0"],
                "default": "2.0",
                "description": "Target QUIPU protocol version.",
            },
            "admin_tier": {
                "type": "string",
                "enum": ["working", "summary", "hybrid"],
                "description": "Granularity tier for upgrade.",
            },
            "tag": {
                "type": "string",
                "description": "Optional domain tag for upgrade.",
            },
            "hub": {
                "type": "string",
                "description": "Optional federation hub identifier for upgrade.",
            },
            "auto_table": {
                "type": "boolean",
                "default": True,
                "description": "Automatically compile homogeneous record lists to @table.",
            },
            "require_seal": {
                "type": "boolean",
                "description": "Override seal verification strictness for verify.",
            },
        },
        "required": ["action"],
    },
}


def _require_str_arg(arguments: dict[str, Any], key: str, action: str) -> str:
    val = arguments.get(key)
    if not isinstance(val, str):
        raise ValueError(f"Parameter '{key}' (str) is required for action '{action}'")
    return val


def _opt_str_arg(arguments: dict[str, Any], key: str) -> str | None:
    val = arguments.get(key)
    if val is None:
        return None
    if not isinstance(val, str):
        raise ValueError(f"Parameter '{key}' must be a string")
    return val


def _opt_bool_arg(arguments: dict[str, Any], key: str, default: bool | None) -> bool | None:
    if key not in arguments or arguments[key] is None:
        return default
    val = arguments[key]
    if not isinstance(val, bool):
        raise ValueError(f"Parameter '{key}' must be a boolean")
    return val


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class QuipuMCPServer:
    """Zero-dependency JSON-RPC 2.0 MCP server exposing the `quipu_codec` tool."""

    def __init__(self) -> None:
        self._action_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "verify": self._action_verify,
            "encode": self._action_encode,
            "decode": self._action_decode,
            "from_json": self._action_from_json,
            "to_json": self._action_to_json,
            "micro": self._action_micro,
            "draw": self._action_draw,
            "benchmark": self._action_benchmark,
            "upgrade": self._action_upgrade,
            "downgrade": self._action_downgrade,
            "distill": self._action_distill,
        }

    def _action_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "verify")
        require_seal = _opt_bool_arg(args, "require_seal", None)
        return verify_quipu(quipu_text, require_seal=require_seal)

    def _encode_value_response(self, value: Any, args: dict[str, Any]) -> dict[str, Any]:
        doc_id = _opt_str_arg(args, "doc_id") or "root"
        mode = _opt_str_arg(args, "mode") or "sealed"
        version = normalize_quipu_version(_opt_str_arg(args, "version") or DEFAULT_QUIPU_VERSION)
        auto_table = bool(_opt_bool_arg(args, "auto_table", True))
        wire = dumps_quipu(
            value,
            doc_id=doc_id,
            mode=mode,
            auto_table=auto_table,
            version=version,
        )
        return {"quipu_text": wire, "doc_id": doc_id, "mode": mode, "version": version}

    def _action_encode(self, args: dict[str, Any]) -> dict[str, Any]:
        if "data" not in args:
            raise ValueError("Parameter 'data' is required for action 'encode'")
        return self._encode_value_response(args["data"], args)

    def _action_decode(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "decode")
        return {"data": loads_quipu(quipu_text)}

    def _action_from_json(self, args: dict[str, Any]) -> dict[str, Any]:
        json_text = _require_str_arg(args, "json_text", "from_json")
        return self._encode_value_response(json.loads(json_text), args)

    def _action_to_json(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "to_json")
        return {"json_text": quipu_to_json(quipu_text)}

    def _action_micro(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "micro")
        return {"micro": render_quipu_micro(parse_quipu(quipu_text))}

    def _action_draw(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "draw")
        return {"ascii": render_quipu_ascii(quipu_text)}

    def _action_benchmark(self, args: dict[str, Any]) -> dict[str, Any]:
        if "data" in args:
            target = args["data"]
        elif isinstance(args.get("json_text"), str):
            target = json.loads(args["json_text"])
        elif isinstance(args.get("quipu_text"), str):
            target = loads_quipu(args["quipu_text"])
        else:
            target = loads_quipu(sample_quipu())
        return benchmark_quipu_vs_json(target)

    def _action_upgrade(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "upgrade")
        doc = upgrade_quipu_to_v2(
            quipu_text,
            admin_tier=_opt_str_arg(args, "admin_tier"),
            tag=_opt_str_arg(args, "tag"),
            hub=_opt_str_arg(args, "hub"),
        )
        return {
            "action": "upgrade",
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "quipu_text": dump_quipu(doc, recompute_seal=False),
        }

    def _action_downgrade(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "downgrade")
        doc = downgrade_quipu_to_v1(quipu_text)
        return {
            "action": "downgrade",
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "quipu_text": dump_quipu(doc, recompute_seal=False),
        }

    def _action_distill(self, args: dict[str, Any]) -> dict[str, Any]:
        quipu_text = _require_str_arg(args, "quipu_text", "distill")
        doc = distill_working_to_summary(quipu_text, doc_id=_opt_str_arg(args, "doc_id"))
        return {
            "action": "distill",
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "quipu_text": dump_quipu(doc, recompute_seal=False),
        }

    def call_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Executes a `quipu_codec` action and returns the structured result dict."""
        action = arguments.get("action")
        if not isinstance(action, str) or action not in self._action_handlers:
            allowed = ", ".join(QUIPU_ACTIONS)
            raise ValueError(f"Unsupported action {action!r}; expected one of: {allowed}")
        return self._action_handlers[action](arguments)

    def _handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        tool_name = params.get("name")
        if tool_name != "quipu_codec":
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name!r}")
        raw_args = params.get("arguments")
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, dict):
            return _jsonrpc_error(req_id, -32602, "Tool arguments must be an object")
        try:
            payload = self.call_tool(raw_args)
            text = json.dumps(payload, indent=2, ensure_ascii=False)
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": payload,
                    "isError": False,
                },
            )
        except (QuipuError, ValueError, TypeError, json.JSONDecodeError) as exc:
            err_payload = {"error": str(exc)}
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps(err_payload, ensure_ascii=False)}
                    ],
                    "structuredContent": err_payload,
                    "isError": True,
                },
            )

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handles a single decoded JSON-RPC 2.0 message; returns None for notifications."""
        method = request.get("method")
        if not isinstance(method, str):
            return _jsonrpc_error(request.get("id"), -32600, "Invalid Request: missing method")
        if "id" not in request:
            return None
        req_id = request["id"]
        if method == "initialize":
            return _jsonrpc_result(
                req_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )
        if method == "ping":
            return _jsonrpc_result(req_id, {})
        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": [QUIPU_TOOL_SPEC]})
        if method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict):
                return _jsonrpc_error(req_id, -32602, "Invalid params for tools/call")
            return self._handle_tools_call(req_id, params)
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def serve_mcp_stdio(
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
) -> int:
    """Runs the newline-delimited JSON-RPC 2.0 MCP server loop over stdio."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    server = QuipuMCPServer()
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        response: dict[str, Any] | None
        try:
            decoded = json.loads(line)
            if not isinstance(decoded, dict):
                response = _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object")
            else:
                response = server.handle_request(decoded)
        except json.JSONDecodeError as exc:
            response = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
        if response is not None:
            out_stream.write(json.dumps(response, ensure_ascii=False) + "\n")
            out_stream.flush()
    return 0
