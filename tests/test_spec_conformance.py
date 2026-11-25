"""Automated conformance tests keeping docs/SPECIFICATION.md synchronized with src/quipu/."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from quipu import MAX_ASCII_CHARS
from quipu.ast_nodes import (
    MAX_ALIAS_EXPANSIONS,
    MAX_COMPOUND_SUM_DEPTH,
    MAX_QUIPU_BYTES,
    MAX_QUIPU_DEPTH,
    MAX_WORKING_ROWS,
)
from quipu.cli import _QUIPU_CLI_ACTIONS
from quipu.codec import (
    compute_quipu_seal,
    loads_quipu,
    parse_quipu,
    serialize_quipu_body,
)
from quipu.mcp_server import MCP_PROTOCOL_VERSION, QUIPU_ACTIONS
from quipu.verifier import verify_quipu

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "docs" / "SPECIFICATION.md"

_POS_WIRE_RE = re.compile(
    r"<!--\s*quipu-vector:pos:(V\d+)\s*-->\s*```quipu\n(.*?)```",
    re.DOTALL,
)
_POS_JSON_RE = re.compile(
    r"<!--\s*quipu-json:pos:(V\d+)\s*-->\s*```json\n(.*?)```",
    re.DOTALL,
)
_NEG_BLOCK_RE = re.compile(
    r"<!--\s*quipu-neg-table:start\s*-->(.*?)<!--\s*quipu-neg-table:end\s*-->",
    re.DOTALL,
)


def _load_spec() -> str:
    assert SPEC_PATH.is_file(), f"Missing specification file at {SPEC_PATH}"
    return SPEC_PATH.read_text(encoding="utf-8")


def _extract_positive_vectors(spec_text: str) -> list[tuple[str, str, str]]:
    wires = dict(_POS_WIRE_RE.findall(spec_text))
    jsons = dict(_POS_JSON_RE.findall(spec_text))
    assert len(wires) >= 6, f"Expected >= 6 positive vectors, found {len(wires)}"
    assert set(wires.keys()) == set(jsons.keys()), "Mismatch between positive wire and JSON blocks"
    return [(vid, wires[vid], jsons[vid]) for vid in sorted(wires.keys())]


def _extract_negative_vectors(spec_text: str) -> list[tuple[str, str, str]]:
    match = _NEG_BLOCK_RE.search(spec_text)
    assert match is not None, "Missing negative test vector table markers in SPECIFICATION.md"
    rows: list[tuple[str, str, str]] = []
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip()
        if not line.startswith("| `NEG-"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        vec_id = cells[0].strip("`")
        expected_col = cells[1]
        wire_escaped = cells[2].strip("`")
        wire = wire_escaped.replace("\\n", "\n")
        rows.append((vec_id, expected_col, wire))
    assert len(rows) == 12, f"Expected 12 negative test vectors, found {len(rows)}"
    return rows


def test_spec_positive_golden_vectors() -> None:
    spec_text = _load_spec()
    for vec_id, wire, expected_json in _extract_positive_vectors(spec_text):
        assert "<LOCK_" not in wire, f"Unlocked placeholder hash found in {vec_id}"
        doc = parse_quipu(wire)
        report = verify_quipu(wire)
        assert report["valid"] is True, f"{vec_id} failed verification: {report['findings']}"
        assert loads_quipu(wire) == json.loads(expected_json), f"{vec_id} JSON projection mismatch"

        if doc.seal is not None:
            expected_seal = compute_quipu_seal(serialize_quipu_body(doc, include_header=True))
            assert doc.seal.knot == expected_seal.knot, f"{vec_id} knot mismatch"
            assert doc.seal.sha256 == expected_seal.sha256, f"{vec_id} sha256 mismatch"


def test_spec_negative_vectors() -> None:
    spec_text = _load_spec()
    for vec_id, expected_col, wire in _extract_negative_vectors(spec_text):
        report = verify_quipu(wire)
        assert report["valid"] is False, f"{vec_id} unexpectedly passed verification"
        found_laws = {f["law"] for f in report["findings"]}

        if "QuipuSyntaxError" in expected_col:
            with pytest.raises(Exception) as exc_info:
                parse_quipu(wire)
            assert exc_info.type.__name__ == "QuipuSyntaxError", f"{vec_id} wrong exception type"
            assert "QLAW_00_SYNTAX" in found_laws, (
                f"{vec_id} expected QLAW_00_SYNTAX, got {found_laws}"
            )
        else:
            expected_law = expected_col.strip("`")
            assert expected_law in found_laws, f"{vec_id} expected {expected_law}, got {found_laws}"


def test_spec_constants_cli_and_mcp_parity() -> None:
    spec_text = _load_spec()

    expected_constants = {
        "MAX_QUIPU_BYTES": f"`{MAX_QUIPU_BYTES:_}`",
        "MAX_QUIPU_DEPTH": f"`{MAX_QUIPU_DEPTH}`",
        "MAX_ALIAS_EXPANSIONS": f"`{MAX_ALIAS_EXPANSIONS:_}`",
        "MAX_COMPOUND_SUM_DEPTH": f"`{MAX_COMPOUND_SUM_DEPTH}`",
        "MAX_WORKING_ROWS": f"`{MAX_WORKING_ROWS:_}`",
        "MAX_ASCII_CHARS": f"`{MAX_ASCII_CHARS:_}`",
    }
    for name, formatted_val in expected_constants.items():
        assert name in spec_text, f"Missing constant name {name} in SPECIFICATION.md"
        assert formatted_val in spec_text, (
            f"Missing constant value {formatted_val} for {name} in SPECIFICATION.md"
        )

    assert MCP_PROTOCOL_VERSION in spec_text
    for cli_act in _QUIPU_CLI_ACTIONS:
        assert f"| `{cli_act}` |" in spec_text, f"CLI action {cli_act!r} missing from spec table"
    for mcp_act in QUIPU_ACTIONS:
        assert f"`{mcp_act}`" in spec_text, f"MCP action {mcp_act!r} missing from spec"

    # Guardrail: no Mermaid blocks or local path leakage in specification
    assert "```mermaid" not in spec_text.lower()
    assert "wsl.localhost" not in spec_text
