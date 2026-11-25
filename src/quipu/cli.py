"""quipu.cli — Standalone CLI for QUIPU/2.0 & QUIPU/1.0 (.quipu) Format & Verification.

Supports `sample`, `verify`, `from-json`, `to-json`, `bench`, `micro`, `upgrade`,
`downgrade`, `distill`, and `mcp`. Enforces CWE-22 path containment within the
current working directory, user home directory, or system temp directory.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .ast_nodes import DEFAULT_QUIPU_VERSION, QuipuError
from .codec import (
    dump_quipu,
    json_to_quipu,
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
from .mcp_server import serve_mcp_stdio
from .verifier import benchmark_quipu_vs_json, verify_quipu

_QUIPU_CLI_ACTIONS = (
    "sample",
    "verify",
    "from-json",
    "to-json",
    "bench",
    "micro",
    "draw",
    "upgrade",
    "downgrade",
    "distill",
    "mcp",
)


def _resolve_cli_path(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser().resolve()
    allowed_roots = [
        Path.cwd().resolve(),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not any(candidate == root or candidate.is_relative_to(root) for root in allowed_roots):
        raise PermissionError(f"Path '{raw_path}' escapes sanctioned roots (CWE-22 guard)")
    if not candidate.is_file():
        raise FileNotFoundError(f"File not found: {raw_path}")
    return candidate


def _load_text_or_sample(file_arg: str | None) -> str:
    if not file_arg:
        return sample_quipu()
    return _resolve_cli_path(file_arg).read_text(encoding="utf-8")


def _handle_compat_action(action: str, args: argparse.Namespace, as_json: bool) -> int:
    raw = _load_text_or_sample(getattr(args, "file", None))
    if action == "upgrade":
        doc = upgrade_quipu_to_v2(
            raw,
            admin_tier=getattr(args, "admin_tier", None),
            tag=getattr(args, "tag", None),
            hub=getattr(args, "hub", None),
        )
    elif action == "downgrade":
        doc = downgrade_quipu_to_v1(raw)
    else:
        doc = distill_working_to_summary(raw)
    wire = dump_quipu(doc, recompute_seal=False)
    if as_json:
        payload = {
            "action": action,
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "wire": wire,
            "quipu_text": wire,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(wire, end="")
    return 0


def _action_sample(args: argparse.Namespace, as_json: bool) -> int:
    fmt_ver = getattr(args, "format_version", DEFAULT_QUIPU_VERSION) or DEFAULT_QUIPU_VERSION
    wire = sample_quipu(version=fmt_ver)
    if as_json:
        doc = parse_quipu(wire)
        print(json.dumps({"wire": wire, "ast": doc.to_dict()}, indent=2, ensure_ascii=False))
    else:
        print(wire, end="")
    return 0


def _action_verify(args: argparse.Namespace, as_json: bool) -> int:
    raw = _load_text_or_sample(getattr(args, "file", None))
    report = verify_quipu(raw)
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["valid"] else 1
    status = "OK" if report["valid"] else "FAIL"
    print(
        f"[{status}] QUIPU [{report['verdict']}] ver={report.get('version')} "
        f"id={report.get('doc_id')} mode={report.get('mode')} "
        f"knot={report.get('knot')} findings={report['findings_count']}"
    )
    for finding in report.get("findings", []):
        print(f"  - [{finding['law']} @ {finding['path']}] {finding['message']}")
    return 0 if report["valid"] else 1


def _action_to_json(args: argparse.Namespace, _as_json: bool) -> int:
    raw = _load_text_or_sample(getattr(args, "file", None))
    print(quipu_to_json(raw))
    return 0


def _action_micro(args: argparse.Namespace, as_json: bool) -> int:
    raw = _load_text_or_sample(getattr(args, "file", None))
    micro = render_quipu_micro(parse_quipu(raw))
    print(json.dumps({"micro": micro}, indent=2, ensure_ascii=False) if as_json else micro)
    return 0


def _action_draw(args: argparse.Namespace, as_json: bool) -> int:
    raw = _load_text_or_sample(getattr(args, "file", None))
    max_rows = max(1, int(getattr(args, "max_rows", 8) or 8))
    diagram = render_quipu_ascii(raw, max_rows=max_rows)
    print(json.dumps({"ascii": diagram}, indent=2, ensure_ascii=False) if as_json else diagram)
    return 0


def _action_from_json(args: argparse.Namespace, as_json: bool) -> int:
    file_arg = getattr(args, "file", None)
    if not file_arg:
        print("Error: --file is required for 'quipu from-json'", file=sys.stderr)
        return 1
    raw_json = _resolve_cli_path(file_arg).read_text(encoding="utf-8")
    mode = getattr(args, "mode", "sealed") or "sealed"
    fmt_ver = getattr(args, "format_version", DEFAULT_QUIPU_VERSION) or DEFAULT_QUIPU_VERSION
    wire = json_to_quipu(raw_json, mode=mode, version=fmt_ver)
    if as_json:
        print(
            json.dumps(
                {"wire": wire, "mode": mode, "version": fmt_ver},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(wire, end="")
    return 0


def _action_bench(args: argparse.Namespace, as_json: bool) -> int:
    file_arg = getattr(args, "file", None)
    raw_text = (
        _resolve_cli_path(file_arg).read_text(encoding="utf-8") if file_arg else sample_quipu()
    )
    decoded_text = quipu_to_json(raw_text) if raw_text.lstrip().startswith("~=") else raw_text
    report = benchmark_quipu_vs_json(json.loads(decoded_text))
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(
            f"QUIPU vs JSON: pretty={report['json_pretty_chars']}B, "
            f"quipu_lax={report['quipu_lax_chars']}B "
            f"({report['savings_vs_pretty_json_pct']}% saved), "
            f"sealed={report['quipu_sealed_chars']}B, roundtrip={report['roundtrip_exact']}"
        )
    return 0


def _dispatch_quipu_action(action: str, args: argparse.Namespace, as_json: bool) -> int:
    if action == "mcp":
        return serve_mcp_stdio()
    handlers = {
        "sample": _action_sample,
        "verify": _action_verify,
        "to-json": _action_to_json,
        "micro": _action_micro,
        "draw": _action_draw,
        "from-json": _action_from_json,
        "bench": _action_bench,
    }
    handler = handlers.get(action)
    if handler is not None:
        return handler(args, as_json)
    if action in ("upgrade", "downgrade", "distill"):
        return _handle_compat_action(action, args, as_json)
    return 0


def cmd_quipu(args: argparse.Namespace) -> int:
    """Executes a parsed QUIPU CLI command and returns a process exit code."""
    action = getattr(args, "quipu_action", "sample") or "sample"
    as_json = bool(getattr(args, "json", False))
    try:
        return _dispatch_quipu_action(action, args, as_json)
    except (
        QuipuError,
        PermissionError,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        if as_json:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        else:
            print(f"QUIPU Error: {exc}", file=sys.stderr)
        return 1


def _add_quipu_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", default=None, help="Path to a .quipu or .json file")
    parser.add_argument(
        "--max-rows",
        dest="max_rows",
        type=int,
        default=8,
        help="Maximum rows per table to display in 'quipu draw' (default: 8)",
    )
    parser.add_argument(
        "--mode",
        default="sealed",
        choices=["sealed", "lax"],
        help="Serialization mode for from-json",
    )
    parser.add_argument(
        "--format-version",
        dest="format_version",
        default="2.0",
        choices=["1.0", "2.0", "QUIPU/1.0", "QUIPU/2.0"],
        help="Target QUIPU protocol version for sample or from-json (default: 2.0)",
    )
    parser.add_argument(
        "--admin-tier",
        dest="admin_tier",
        default=None,
        choices=["working", "summary", "hybrid"],
        help="Optional administrative granularity tier for upgrade",
    )
    parser.add_argument("--tag", default=None, help="Optional domain tag for upgrade")
    parser.add_argument("--hub", default=None, help="Optional hub identifier for upgrade")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the standalone `quipu` CLI."""
    parser = argparse.ArgumentParser(
        prog="quipu",
        description="QUIPU/2.0 & QUIPU/1.0 Standalone Codec, Verifier & MCP Server",
    )
    sub = parser.add_subparsers(dest="quipu_action")
    for act in _QUIPU_CLI_ACTIONS:
        subparser = sub.add_parser(act)
        if act != "mcp":
            _add_quipu_flags(subparser)
    args = parser.parse_args(argv)
    if not getattr(args, "quipu_action", None):
        args.quipu_action = "sample"
        args.file = None
        args.mode = "sealed"
        args.format_version = "2.0"
        args.json = False
    return cmd_quipu(args)


if __name__ == "__main__":
    raise SystemExit(main())
