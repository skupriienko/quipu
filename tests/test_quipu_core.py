"""Core codec, bijection, base-10 knot, and safety-bound tests for `quipu`."""

from __future__ import annotations

import io
import json
import math

import pytest

import quipu
from quipu import (
    MAX_ALIAS_EXPANSIONS,
    MAX_QUIPU_DEPTH,
    CordAlias,
    CordAttachment,
    CordMeta,
    CordPolarity,
    CordSpin,
    CordTier,
    QuipuDocument,
    QuipuMode,
    QuipuNode,
    QuipuSyntaxError,
    QuipuTable,
    TopCordSpec,
    decode_knots,
    dump,
    dumps,
    encode_7bit,
    encode_14bit,
    encode_knots,
    json_to_quipu,
    load,
    loads,
    parse_quipu,
    project_quota_population,
    quantize_bucket,
    quipu_to_json,
    verify,
)


def test_json_bijection_nested_types_and_bool_vs_int() -> None:
    payload = {
        "service": "edge-router",
        "empty_map": {},
        "empty_list": [],
        "scalars": {
            "none_val": None,
            "flag_true": True,
            "flag_false": False,
            "zero": 0,
            "one": 1,
            "neg": -42,
            "ratio": 3.14159,
            "unicode": 'alpha \u2192 omega "quoted"',
        },
        "nested_list": [1, True, 0, False, None, {"inner": [10, 20.5]}],
        "records": [
            {"id": 1, "active": True, "score": 9.5, "note": "ok"},
            {"id": 2, "active": False, "score": None, "note": None},
            {"id": 3, "active": True, "score": 7.0, "note": "pass"},
        ],
    }

    wire = dumps(payload, doc_id="core.bijection")
    assert verify(wire)["valid"] is True

    decoded = loads(wire)
    assert decoded == payload
    assert type(decoded["scalars"]["flag_true"]) is bool
    assert type(decoded["scalars"]["one"]) is int
    assert type(decoded["scalars"]["flag_false"]) is bool
    assert type(decoded["scalars"]["zero"]) is int
    assert type(decoded["nested_list"][0]) is int
    assert type(decoded["nested_list"][1]) is bool
    assert type(decoded["records"][0]["active"]) is bool
    assert type(decoded["records"][0]["id"]) is int

    json_roundtrip = json.loads(quipu_to_json(json_to_quipu(json.dumps(payload))))
    assert json_roundtrip == payload


def test_stream_load_and_dump_via_stringio() -> None:
    payload = {
        "name": "stream-check",
        "counts": [10, 20, 30],
        "items": [
            {"k": "a", "v": 1},
            {"k": "b", "v": 2},
        ],
    }
    buf = io.StringIO()
    dump(payload, buf, doc_id="stream.doc", mode="sealed")
    buf.seek(0)
    assert load(buf) == payload


def test_comments_trailing_commas_and_headerless_lax_mode() -> None:
    raw = """
# Top-level comment
service: "gateway", # inline comment
tags: [
  "alpha",
  "beta", # trailing comma in list
],
config: {
  retries: 3,
  enabled: true, # trailing comma in map
},
metrics: @table(name:str, count:int, ok:bool) ^count=2 ^sum(count)=15 {
  "fast" | 10 | true
  "slow" | 5 | false
}
"""
    doc = parse_quipu(raw)
    assert doc.mode == QuipuMode.LAX
    report = verify(raw)
    assert report["valid"] is True
    assert report["mode"] == "lax"

    decoded = loads(raw)
    assert decoded == {
        "service": "gateway",
        "tags": ["alpha", "beta"],
        "config": {"retries": 3, "enabled": True},
        "metrics": [
            {"name": "fast", "count": 10, "ok": True},
            {"name": "slow", "count": 5, "ok": False},
        ],
    }

    lax_wire = dumps(decoded, mode="lax", include_header=False)
    assert not lax_wire.lstrip().startswith("~=")
    assert loads(lax_wire) == decoded
    assert verify(lax_wire)["valid"] is True


def test_knots_registers_buckets_and_quota_projection() -> None:
    assert encode_knots(0) == "0M-0C-0D-0U"
    assert encode_knots(1, figure_eight_unit=True) == "0M-0C-0D-1E"
    assert encode_knots(121, figure_eight_unit=True) == "0M-1C-2D-1E"
    assert encode_knots(-2045) == "-2M-0C-4D-5U"

    for sample in (0, 1, 17, 121, 999, 2045, -42):
        encoded = encode_knots(sample, figure_eight_unit=(abs(sample) % 10 == 1))
        assert decode_knots(encoded) == sample
    assert decode_knots("0M-0C-0D-1E") == 1

    with pytest.raises(ValueError, match="non-boolean int"):
        encode_knots(True)
    with pytest.raises(ValueError, match="Invalid knot notation"):
        decode_knots("bad-knots")

    assert encode_7bit(CordSpin.Z, CordTier.T0, has_numeric=True, is_table=False) == "1010011"
    assert encode_7bit(CordSpin.S, CordTier.T3, has_numeric=False, is_table=True) == "1101101"

    meta = CordMeta(
        spin=CordSpin.S,
        tier=CordTier.T2,
        anchor="anchor_a",
        attachment=CordAttachment.R,
        polarity=CordPolarity.WHITE,
        unit="usd",
        nether=10,
    )
    reg14 = encode_14bit(meta, has_numeric=True, is_table=True)
    assert len(reg14) == 14
    assert reg14.startswith("1101011")
    assert reg14[7:] == "1111111"

    assert quantize_bucket(0) == 0
    assert quantize_bucket(-5) == 0
    assert quantize_bucket(1) == 1
    assert quantize_bucket(11) == 15
    assert quantize_bucket(41) == 50
    assert quantize_bucket(5000) == 1000
    with pytest.raises(ValueError, match="non-boolean int"):
        quantize_bucket(False)

    assert project_quota_population(45, quota_pct=22.5) == pytest.approx(200.0)
    with pytest.raises(ValueError, match="quota_pct must be in"):
        project_quota_population(10, quota_pct=0.0)


def test_safety_bounds_nul_depth_and_non_finite_floats() -> None:
    with pytest.raises(QuipuSyntaxError, match="Null byte"):
        parse_quipu('a: "hello\x00world"')
    nul_report = verify('a: "bad\x00"')
    assert nul_report["valid"] is False
    assert nul_report["verdict"] == "SAFETY_VIOLATION"
    assert nul_report["findings"][0]["law"] == "QLAW_07_SAFETY_BOUNDS"

    deep: dict[str, object] = {"leaf": 1}
    for _ in range(MAX_QUIPU_DEPTH + 1):
        deep = {"wrap": deep}
    with pytest.raises(QuipuSyntaxError, match="MAX_QUIPU_DEPTH"):
        dumps(deep)

    deep_wire = (
        " ".join(["{ a:"] * (MAX_QUIPU_DEPTH + 2)) + " 1 " + " ".join(["}"] * (MAX_QUIPU_DEPTH + 2))
    )
    depth_report = verify(deep_wire)
    assert depth_report["valid"] is False
    assert depth_report["findings"][0]["law"] == "QLAW_07_SAFETY_BOUNDS"

    with pytest.raises(QuipuSyntaxError, match="Non-finite float"):
        dumps({"bad": math.nan})
    with pytest.raises(QuipuSyntaxError, match="Non-finite float"):
        dumps({"bad": math.inf})

    nan_doc = QuipuDocument(
        mode=QuipuMode.LAX,
        root=QuipuNode(value={"bad": QuipuNode(value=math.nan)}),
    )
    nan_report = verify(nan_doc)
    assert nan_report["valid"] is False
    assert any(f["law"] == "QLAW_07_SAFETY_BOUNDS" for f in nan_report["findings"])


def test_cyclic_alias_and_expansion_cap() -> None:
    cyclic_wire = """
~= QUIPU/2.0 id="cycle" mode=lax
a &a: { next: *b }
b &b: { next: *a }
"""
    cyc_report = verify(cyclic_wire)
    assert cyc_report["valid"] is False
    assert any(f["law"] == "QLAW_04_ACYCLIC_ALIASES" for f in cyc_report["findings"])
    with pytest.raises(QuipuSyntaxError, match="Cyclic alias"):
        loads(cyclic_wire)

    # Branching factor 3 across 7 levels yields 3^1 + ... + 3^7 = 3279 expansions (> 1024)
    # while remaining under MAX_COMPOUND_SUM_DEPTH (10).
    bomb_lines = ['~= QUIPU/2.0 id="bomb" mode=lax', 'n0 &n0: "x"']
    for lvl in range(1, 8):
        prev = f"*n{lvl - 1}"
        bomb_lines.append(f"n{lvl} &n{lvl}: [{prev}, {prev}, {prev}]")
    bomb_wire = "\n".join(bomb_lines) + "\n"

    bomb_report = verify(bomb_wire)
    assert bomb_report["valid"] is False
    assert any(
        f["law"] == "QLAW_04_ACYCLIC_ALIASES" and str(MAX_ALIAS_EXPANSIONS) in f["message"]
        for f in bomb_report["findings"]
    )
    with pytest.raises(QuipuSyntaxError, match="Alias expansion budget exceeded"):
        loads(bomb_wire)


def test_duplicate_keys_taint_spin_and_column_type_violations() -> None:
    with pytest.raises(QuipuSyntaxError, match="Duplicate key"):
        parse_quipu("dup: 1\ndup: 2\n")
    with pytest.raises(QuipuSyntaxError, match="Duplicate key"):
        parse_quipu("outer: { x: 1, x: 2 }\n")

    taint_wire = """
~= QUIPU/2.0 id="taint" mode=lax
untrusted &ext @T2: { token: "raw" }
trusted @T0: *ext
"""
    taint_report = verify(taint_wire)
    assert taint_report["valid"] is False
    assert any(f["law"] == "QLAW_06_TAINT_NON_ESCALATION" for f in taint_report["findings"])

    spin_wire = """
~= QUIPU/2.0 id="spin" mode=lax
frozen ~Z: {
  illegal ~S: 42
}
"""
    spin_report = verify(spin_wire)
    assert spin_report["valid"] is False
    assert any(f["law"] == "QLAW_05_SPIN_CONTAINMENT" for f in spin_report["findings"])

    bad_table_doc = QuipuDocument(
        mode=QuipuMode.LAX,
        root=QuipuNode(
            value={
                "rows": QuipuNode(
                    value=QuipuTable(
                        columns=[("id", "int"), ("flag", "bool")],
                        rows=[[True, True], [2, False]],
                        top_cords=[TopCordSpec(kind="count", column=None, expected=2)],
                    )
                )
            }
        ),
    )
    col_report = verify(bad_table_doc)
    assert col_report["valid"] is False
    assert any(f["law"] == "QLAW_03_COLUMN_TYPES" for f in col_report["findings"])

    bad_knot_wire = """
~= QUIPU/2.0 id="knot" mode=lax
count ^knots="0M-0C-0D-5U": 4
"""
    knot_report = verify(bad_knot_wire)
    assert knot_report["valid"] is False
    assert any(f["law"] == "QLAW_02_TOP_CORD_ARITHMETIC" for f in knot_report["findings"])

    tampered_sealed = quipu.sample_quipu().replace("2026.11.25", "2026.11.26")
    seal_report = verify(tampered_sealed)
    assert seal_report["valid"] is False
    assert any(f["law"] == "QLAW_01_MERKLE_SEAL" for f in seal_report["findings"])


def test_unresolved_alias_and_duplicate_anchor() -> None:
    unresolved = QuipuDocument(
        mode=QuipuMode.LAX,
        root=QuipuNode(value={"ref": QuipuNode(value=CordAlias(target="missing"))}),
    )
    report = verify(unresolved)
    assert report["valid"] is False
    assert any(f["law"] == "QLAW_04_ACYCLIC_ALIASES" for f in report["findings"])
