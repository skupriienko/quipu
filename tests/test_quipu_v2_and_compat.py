"""QUIPU/2.0 features, strict QUIPU/1.0 isolation, and compatibility shim tests."""

from __future__ import annotations

import math

import pytest

from quipu import (
    DEFAULT_QUIPU_VERSION,
    MAX_COMPOUND_SUM_DEPTH,
    MAX_WORKING_ROWS,
    QUIPU_V1,
    QUIPU_V2,
    AdminTier,
    CordMeta,
    QuipuDocument,
    QuipuMode,
    QuipuNode,
    QuipuSyntaxError,
    QuipuTable,
    detect_quipu_version,
    distill_working_to_summary,
    downgrade_quipu_to_v1,
    dump_quipu,
    is_quipu_v1,
    is_quipu_v2,
    link_quipus,
    loads,
    parse_quipu,
    sample_quipu,
    sample_quipu_v1,
    upgrade_quipu_to_v2,
    verify,
)


def test_default_version_and_law_counts() -> None:
    assert DEFAULT_QUIPU_VERSION == QUIPU_V2 == "QUIPU/2.0"

    v1_rep = verify(sample_quipu_v1())
    v2_rep = verify(sample_quipu())

    assert v1_rep["valid"] is True
    assert v1_rep["version"] == QUIPU_V1
    assert len(v1_rep["laws_checked"]) == 7

    assert v2_rep["valid"] is True
    assert v2_rep["version"] == QUIPU_V2
    assert len(v2_rep["laws_checked"]) == 10
    assert set(v2_rep["laws_checked"][-3:]) == {
        "QLAW_08_BALANCE_BOUNDS",
        "QLAW_09_ACYCLIC_SUM_DAG",
        "QLAW_10_HEADER_TIER_AND_LINEAGE",
    }


@pytest.mark.parametrize(
    ("wire", "match_msg"),
    [
        ('~= QUIPU/1.0 id="h1" mode=lax tier=working\na: 1\n', "requires QUIPU/2.0"),
        ('~= QUIPU/1.0 id="h2" mode=lax tag="ops"\na: 1\n', "requires QUIPU/2.0"),
        (
            '~= QUIPU/1.0 id="h3" mode=lax parent="quipu-0123456789ab"\na: 1\n',
            "requires QUIPU/2.0",
        ),
        ('~= QUIPU/1.0 id="h4" mode=lax hub="HubA"\na: 1\n', "requires QUIPU/2.0"),
        ('~= QUIPU/1.0 id="d1" mode=lax\n{\n  a ~R: 1\n}\n', "only supported in QUIPU/2.0"),
        ('~= QUIPU/1.0 id="d2" mode=lax\n{\n  a ~V: 1\n}\n', "only supported in QUIPU/2.0"),
        ('~= QUIPU/1.0 id="d3" mode=lax\n{\n  a @W: 1\n}\n', "only supported in QUIPU/2.0"),
        ('~= QUIPU/1.0 id="d4" mode=lax\n{\n  a @D: 1\n}\n', "only supported in QUIPU/2.0"),
        (
            '~= QUIPU/1.0 id="d5" mode=lax\n{\n  a ^unit="ms": 10\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="d6" mode=lax\n{\n  a ^wrap="box": 10\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="d7" mode=lax\n{\n  a ^nether=2: 10\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t1" mode=lax\nt: @table(n:int) ^layout="banded" {\n  1\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t2" mode=lax\nt: @table(n:int) {\n  1\n  ---\n  2\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t3" mode=lax\nt: @table(n:int) ^sum(n, 0, 0)=1 {\n  1\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t4" mode=lax\nt: @table(n:int) ^tol(n, pct=5)=1 {\n  1\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t5" mode=lax\nt: @table(c:int, d:int) ^net(c, d)=0 {\n  1 | 1\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            (
                '~= QUIPU/1.0 id="t6" mode=lax\n'
                "t: @table(c:int, d:int) ^equal_sum(c, d)=1 {\n  1 | 1\n}\n"
            ),
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t7" mode=lax\nt: @table(n:int) ^band(n)=2 {\n  1\n  1\n}\n',
            "only supported in QUIPU/2.0",
        ),
        (
            '~= QUIPU/1.0 id="t8" mode=lax\nt: @table(n:int) ^quota(n, pct=50)=2 {\n  1\n}\n',
            "only supported in QUIPU/2.0",
        ),
    ],
)
def test_strict_rejection_of_v2_features_in_v1(wire: str, match_msg: str) -> None:
    with pytest.raises(QuipuSyntaxError, match=match_msg):
        parse_quipu(wire)


def test_v2_headers_decorators_and_table_directives_valid() -> None:
    parent_knot = "quipu-0123456789ab"
    wire = f"""
~= QUIPU/2.0 id="ledger.v2" mode=lax tier=hybrid tag="treasury/q4" parent="{parent_knot}" hub="HubA"

primary ~R @W ^unit="usd" ^wrap="envelope" ^nether=0.5: 100
shadow ~V @D ^unit="usd": 100
ledger: @table(acct:str, credit:int, debit:int, amount:int)
  ^layout="banded" ^count=4 ^sum(amount, 0, 1)=50
  ^net(credit, debit)=0 ^equal_sum(credit, debit)=100
  ^tol(amount, pct=10)=95 ^band(amount, ratio="1/2")=100
  ^quota(amount, pct=25)=400 {{
  "a1" | 50 | 0 | 25
  "a2" | 0 | 50 | 25
  ---
  "b1" | 50 | 0 | 30
  "b2" | 0 | 50 | 20
}}
"""
    doc = parse_quipu(wire)
    assert doc.version == QUIPU_V2
    assert doc.admin_tier == AdminTier.HYBRID
    assert doc.tag == "treasury/q4"
    assert doc.parent == parent_knot
    assert doc.hub == "HubA"

    tbl = doc.root.value["ledger"].value
    assert isinstance(tbl, QuipuTable)
    assert tbl.layout == "banded"
    assert tbl.spacer_indices == [2]

    rep = verify(wire)
    assert rep["valid"] is True, rep["findings"]
    assert len(rep["laws_checked"]) == 10

    re_wire = dump_quipu(doc, recompute_seal=False)
    assert verify(re_wire)["valid"] is True


def test_v2_balance_bounds_qlaw08_violations() -> None:
    tol_breach_wire = """
~= QUIPU/2.0 id="tol_fail" mode=lax
tbl: @table(val:int) ^tol(val, pct=5)=100 {
  60
  50
}
"""
    rep_tol = verify(tol_breach_wire)
    assert rep_tol["valid"] is False
    assert any(
        f["law"] == "QLAW_08_BALANCE_BOUNDS" and "Tolerance breach" in f["message"]
        for f in rep_tol["findings"]
    )

    bad_balance_wire = """
~= QUIPU/2.0 id="bal_fail" mode=lax
tbl: @table(c:int, d:int, amt:int)
  ^sum(amt, 0, 5)=10 ^net(c, d)=10 ^equal_sum(c, d)=10
  ^band(amt, ratio="1/2")=10 ^quota(amt, pct=25)=999 {
  10 | 5 | 8
  ---
  0 | 0 | 2
}
"""
    rep_bal = verify(bad_balance_wire)
    assert rep_bal["valid"] is False
    laws = [f["law"] for f in rep_bal["findings"]]
    assert laws.count("QLAW_08_BALANCE_BOUNDS") >= 5

    nether_nan_doc = QuipuDocument(
        version=QUIPU_V2,
        mode=QuipuMode.LAX,
        root=QuipuNode(value={"x": QuipuNode(value=1, meta=CordMeta(nether=math.nan))}),
    )
    rep_nether = verify(nether_nan_doc)
    assert rep_nether["valid"] is False
    assert any(f["law"] == "QLAW_08_BALANCE_BOUNDS" for f in rep_nether["findings"])


def test_v2_qlaw09_acyclic_sum_dag_and_table_meta() -> None:
    lines = ['~= QUIPU/2.0 id="deep_dag" mode=lax', "a0 &a0: 1"]
    for idx in range(1, MAX_COMPOUND_SUM_DEPTH + 2):
        lines.append(f"a{idx} &a{idx}: *a{idx - 1}")
    rep_dag = verify("\n".join(lines) + "\n")
    assert rep_dag["valid"] is False
    assert any(f["law"] == "QLAW_09_ACYCLIC_SUM_DAG" for f in rep_dag["findings"])

    bad_table_doc = QuipuDocument(
        version=QUIPU_V2,
        mode=QuipuMode.LAX,
        root=QuipuNode(
            value={
                "t": QuipuNode(
                    value=QuipuTable(
                        columns=[("n", "int")],
                        rows=[[1], [2]],
                        spacer_indices=[2, 0],
                        layout="diagonal",
                    )
                )
            }
        ),
    )
    rep_tbl = verify(bad_table_doc)
    assert rep_tbl["valid"] is False
    assert [f["law"] for f in rep_tbl["findings"]].count("QLAW_09_ACYCLIC_SUM_DAG") == 2


def test_v2_qlaw10_header_lineage_and_working_row_ceiling() -> None:
    bad_hdr_wire = """
~= QUIPU/2.0 id="bad_hdr" mode=lax parent="invalid-parent" tag="bad;tag" hub="bad$hub"
x: 1
"""
    rep_hdr = verify(bad_hdr_wire)
    assert rep_hdr["valid"] is False
    assert [f["law"] for f in rep_hdr["findings"]].count("QLAW_10_HEADER_TIER_AND_LINEAGE") == 3

    over_cap_doc = QuipuDocument(
        version=QUIPU_V2,
        mode=QuipuMode.LAX,
        admin_tier=AdminTier.WORKING,
        root=QuipuNode(
            value={
                "rows": QuipuNode(
                    value=QuipuTable(
                        columns=[("i", "int")],
                        rows=[[i] for i in range(MAX_WORKING_ROWS)],
                    )
                )
            }
        ),
    )
    rep_cap = verify(over_cap_doc)
    assert rep_cap["valid"] is False
    assert any(f["law"] == "QLAW_10_HEADER_TIER_AND_LINEAGE" for f in rep_cap["findings"])

    summary_doc = QuipuDocument(
        version=QUIPU_V2,
        mode=QuipuMode.LAX,
        admin_tier=AdminTier.SUMMARY,
        root=over_cap_doc.root,
    )
    assert verify(summary_doc)["valid"] is True


def test_compat_shims_upgrade_downgrade_distill_and_link() -> None:
    v1_wire = sample_quipu_v1()
    v2_wire = sample_quipu()

    assert detect_quipu_version(v1_wire) == QUIPU_V1
    assert is_quipu_v1(v1_wire) is True
    assert is_quipu_v2(v1_wire) is False

    assert detect_quipu_version(v2_wire) == QUIPU_V2
    assert is_quipu_v2(v2_wire) is True
    assert is_quipu_v1(v2_wire) is False

    v1_doc = parse_quipu(v1_wire)
    assert v1_doc.seal is not None
    upgraded = upgrade_quipu_to_v2(v1_wire, admin_tier="working", tag="promoted", hub="HubWest")
    assert upgraded.version == QUIPU_V2
    assert upgraded.admin_tier == AdminTier.WORKING
    assert upgraded.tag == "promoted"
    assert upgraded.hub == "HubWest"
    assert upgraded.parent == v1_doc.seal.knot
    assert verify(dump_quipu(upgraded))["valid"] is True

    downgraded = downgrade_quipu_to_v1(v2_wire)
    assert downgraded.version == QUIPU_V1
    assert downgraded.admin_tier is None
    assert downgraded.tag is None
    downgraded_wire = dump_quipu(downgraded)
    rep_down = verify(downgraded_wire)
    assert rep_down["valid"] is True
    assert len(rep_down["laws_checked"]) == 7
    assert loads(downgraded_wire) == loads(v2_wire)

    v2_doc = parse_quipu(v2_wire)
    assert v2_doc.seal is not None
    summary_doc = distill_working_to_summary(v2_wire, doc_id="release.summary")
    assert summary_doc.doc_id == "release.summary"
    assert summary_doc.admin_tier == AdminTier.SUMMARY
    assert summary_doc.parent == v2_doc.seal.knot
    summary_wire = dump_quipu(summary_doc)
    assert verify(summary_wire)["valid"] is True
    summary_data = loads(summary_wire)
    assert summary_data["metrics"] == {
        "row_count": 3,
        "column_count": 3,
        "band_count": 1,
        "numeric_sums": {"tokens": 176},
    }

    linked = link_quipus({"v1_pkt": v1_wire, "v2_pkt": v2_wire}, hub_id="HubCore")
    linked_wire = dump_quipu(linked)
    assert verify(linked_wire)["valid"] is True
    linked_data = loads(linked_wire)
    assert linked_data["hub_id"] == "HubCore"
    assert len(linked_data["members"]) == 2
    assert {m["slot"] for m in linked_data["members"]} == {"v1_pkt", "v2_pkt"}

    with pytest.raises(ValueError, match="at least one member packet"):
        link_quipus({})
