"""quipu.verifier — 7-Law (QUIPU/1.0) & 10-Law (QUIPU/2.0) Static Verification Engine.

Pure-stdlib deterministic verifier checking:
- QLAW_01_MERKLE_SEAL: Sealed mode SHA-256 + knot reconciliation
- QLAW_02_TOP_CORD_ARITHMETIC: @table ^count/^sum(col) & ^knots="..." parity
- QLAW_03_COLUMN_TYPES: Strict @table cell type conformance (bool != int)
- QLAW_04_ACYCLIC_ALIASES: All *aliases resolve acyclically within CWE-776 cap
- QLAW_05_SPIN_CONTAINMENT: Explicit ~Z containers forbid ~S mutations inside
- QLAW_06_TAINT_NON_ESCALATION: T0/T1 nodes cannot alias T2/T3 anchors
- QLAW_07_SAFETY_BOUNDS: Bounded depth (<= 32), finite floats, zero NUL bytes
- QLAW_08_BALANCE_BOUNDS (QUIPU/2.0): Slice sums, net balance, equal sums, tol, band, quota
- QLAW_09_ACYCLIC_SUM_DAG (QUIPU/2.0): Sorted spacers, valid layout, bounded alias depth (<= 10)
- QLAW_10_HEADER_TIER_AND_LINEAGE (QUIPU/2.0): Safe header metadata, row cap, valid parent
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from .ast_nodes import (
    MAX_ALIAS_EXPANSIONS,
    MAX_COMPOUND_SUM_DEPTH,
    MAX_QUIPU_DEPTH,
    MAX_WORKING_ROWS,
    QUIPU_V2,
    AdminTier,
    CordAlias,
    CordSpin,
    CordTier,
    QuipuDocument,
    QuipuMode,
    QuipuNode,
    QuipuSyntaxError,
    QuipuTable,
    TopCordSpec,
    decode_incan_knots,
    project_quota_population,
    tier_rank,
)
from .codec import (
    compute_quipu_seal,
    dumps_quipu,
    parse_quipu,
    quipu_to_data,
    serialize_quipu_body,
)

_V1_LAWS = [
    "QLAW_01_MERKLE_SEAL",
    "QLAW_02_TOP_CORD_ARITHMETIC",
    "QLAW_03_COLUMN_TYPES",
    "QLAW_04_ACYCLIC_ALIASES",
    "QLAW_05_SPIN_CONTAINMENT",
    "QLAW_06_TAINT_NON_ESCALATION",
    "QLAW_07_SAFETY_BOUNDS",
]

_V2_LAWS = [
    "QLAW_08_BALANCE_BOUNDS",
    "QLAW_09_ACYCLIC_SUM_DAG",
    "QLAW_10_HEADER_TIER_AND_LINEAGE",
]

_PARENT_KNOT_RE = re.compile(r"^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}|none)$")
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9_.\-/: ]{1,128}$")
_VALID_LAYOUTS = frozenset({"banded", "seriated"})
_VALID_BAND_RATIOS: dict[str, float] = {
    "1/2": 0.5,
    "1/3": 1.0 / 3.0,
    "2/3": 2.0 / 3.0,
    "2/5": 0.4,
    "3/5": 0.6,
}


def _add_finding(
    findings: list[dict[str, str]],
    law: str,
    path: str,
    message: str,
    severity: str = "error",
) -> None:
    findings.append({"law": law, "path": path, "severity": severity, "message": message})


def _cell_matches_type(cell: Any, col_type: str) -> bool:
    if col_type == "any":
        return True
    base = col_type[:-1] if col_type.endswith("?") else col_type
    if cell is None:
        return col_type.endswith("?")
    if base == "int":
        return isinstance(cell, int) and not isinstance(cell, bool)
    if base == "float":
        return isinstance(cell, float) and math.isfinite(cell)
    target = {"bool": bool, "str": str}.get(base)
    return target is not None and isinstance(cell, target)


def _numeric_column_values(
    table: QuipuTable, col_name: str, row_slice: slice | None = None
) -> list[int | float] | None:
    c_idx = table.column_index(col_name)
    if c_idx is None:
        return None
    _cname, ctype = table.columns[c_idx]
    if ctype.rstrip("?") not in ("int", "float", "any"):
        return None
    rows = table.rows[row_slice] if row_slice is not None else table.rows
    return [
        r[c_idx]
        for r in rows
        if c_idx < len(r) and isinstance(r[c_idx], (int, float)) and not isinstance(r[c_idx], bool)
    ]


def _num_equal(a: int | float, b: int | float) -> bool:
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-9)


def _check_seal(
    doc: QuipuDocument, require_seal: bool | None, findings: list[dict[str, str]]
) -> None:
    must_verify = (
        require_seal
        if require_seal is not None
        else (doc.mode == QuipuMode.SEALED or doc.seal is not None)
    )
    if not must_verify:
        return
    expected = compute_quipu_seal(serialize_quipu_body(doc, include_header=True))
    if doc.seal is None:
        _add_finding(
            findings,
            "QLAW_01_MERKLE_SEAL",
            "$.seal",
            "Missing '=~' reconciliation seal in sealed mode",
        )
        return
    if doc.seal.sha256 != expected.sha256:
        _add_finding(
            findings,
            "QLAW_01_MERKLE_SEAL",
            "$.seal",
            f"SHA-256 mismatch: declared {doc.seal.sha256[:12]}... != "
            f"computed {expected.sha256[:12]}...",
        )
    if doc.seal.knot != expected.knot:
        _add_finding(
            findings,
            "QLAW_01_MERKLE_SEAL",
            "$.seal",
            f"Knot mismatch: declared {doc.seal.knot} != computed {expected.knot}",
        )
    if not doc.seal.reconciled:
        _add_finding(findings, "QLAW_01_MERKLE_SEAL", "$.seal", "Seal marked reconciled=false")


def _check_v2_header_and_tags(doc: QuipuDocument, findings: list[dict[str, str]]) -> None:
    if doc.version != QUIPU_V2:
        return
    if doc.parent is not None and not _PARENT_KNOT_RE.match(doc.parent):
        _add_finding(
            findings,
            "QLAW_10_HEADER_TIER_AND_LINEAGE",
            "$.header.parent",
            f"Invalid parent knot {doc.parent!r}; expected 'quipu-<12hex>'",
        )
    for label, val in (("tag", doc.tag), ("hub", doc.hub)):
        if val is not None and not _SAFE_TAG_RE.match(val):
            _add_finding(
                findings,
                "QLAW_10_HEADER_TIER_AND_LINEAGE",
                f"$.header.{label}",
                f"Unsafe or malformed header {label}={val!r} (CWE-20 guard)",
            )


def _check_v1_top_cord(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    if tc.kind == "count":
        if len(table.rows) != tc.expected:
            _add_finding(
                findings,
                "QLAW_02_TOP_CORD_ARITHMETIC",
                path,
                f"Top Cord ^count={tc.expected} disagrees with row count {len(table.rows)}",
            )
        return
    if tc.kind == "sum" and tc.start_row is None and tc.end_row is None:
        c_idx = table.column_index(str(tc.column))
        if c_idx is None:
            _add_finding(
                findings,
                "QLAW_02_TOP_CORD_ARITHMETIC",
                path,
                f"Top Cord ^sum({tc.column}) references unknown column",
            )
            return
        vals = _numeric_column_values(table, str(tc.column))
        if vals is None:
            _add_finding(
                findings,
                "QLAW_02_TOP_CORD_ARITHMETIC",
                path,
                f"Top Cord ^sum({tc.column}) requires numeric column",
            )
            return
        actual_sum = sum(vals)
        if not _num_equal(actual_sum, tc.expected):
            _add_finding(
                findings,
                "QLAW_02_TOP_CORD_ARITHMETIC",
                path,
                f"Top Cord ^sum({tc.column})={tc.expected} disagrees with "
                f"computed sum {actual_sum}",
            )


def _check_v2_slice_sum(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    if tc.start_row is None or tc.end_row is None:
        return
    if tc.start_row < 0 or tc.end_row < tc.start_row or tc.end_row >= len(table.rows):
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"Slice ^sum({tc.column}, {tc.start_row}, {tc.end_row}) out of bounds",
        )
        return
    vals = _numeric_column_values(table, str(tc.column), slice(tc.start_row, tc.end_row + 1))
    if vals is None:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"Slice ^sum({tc.column}) requires numeric column",
        )
        return
    if not _num_equal(sum(vals), tc.expected):
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"Slice ^sum({tc.column}, {tc.start_row}, {tc.end_row})={tc.expected} != {sum(vals)}",
        )


def _extract_pct_series(
    table: QuipuTable,
    tc: TopCordSpec,
    default_pct: float,
    directive: str,
    path: str,
    findings: list[dict[str, str]],
) -> tuple[float, float] | None:
    vals = _numeric_column_values(table, str(tc.column))
    pct = float(tc.tolerance_pct if tc.tolerance_pct is not None else default_pct)
    if vals is None or pct <= 0.0 or pct > 100.0:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^{directive}({tc.column}, pct={pct}) invalid",
        )
        return None
    return float(sum(vals)), pct


def _check_v2_tol(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    extracted = _extract_pct_series(table, tc, 5.0, "tol", path, findings)
    if extracted is None:
        return
    actual, pct = extracted
    nominal = float(tc.expected)
    upper = nominal * (1.0 + pct / 100.0) + 1e-9
    if actual + 1e-9 < nominal or actual > upper:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"Tolerance breach on ^tol({tc.column}): "
            f"actual {actual} outside [{nominal}, {upper:.4f}]",
        )


def _check_v2_net(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    v1 = _numeric_column_values(table, str(tc.column))
    v2 = _numeric_column_values(table, str(tc.end_column))
    if v1 is None or v2 is None:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^{tc.kind}({tc.column}, {tc.end_column}) requires numeric columns",
        )
        return
    s1, s2 = sum(v1), sum(v2)
    if tc.kind == "net" and not _num_equal(s1 - s2, tc.expected):
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^net({tc.column}, {tc.end_column})={tc.expected} != credit-debt {s1 - s2}",
        )
    elif tc.kind == "equal_sum" and not (
        _num_equal(s1, tc.expected) and _num_equal(s2, tc.expected)
    ):
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^equal_sum({tc.column}, {tc.end_column})={tc.expected} != ({s1}, {s2})",
        )


def _check_v2_band(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    vals = _numeric_column_values(table, str(tc.column))
    ratio_key = str(tc.ratio or "1/2")
    if vals is None or not table.spacer_indices or ratio_key not in _VALID_BAND_RATIOS:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^band({tc.column}, ratio={ratio_key!r}) requires numeric column, "
            "valid ratio, and '---' spacer",
        )
        return
    total = float(sum(vals))
    split_at = table.spacer_indices[0]
    band_slice = _numeric_column_values(table, str(tc.column), slice(0, split_at)) or []
    first_band = float(sum(band_slice))
    ratio_ok = total > 0.0 and math.isclose(
        first_band / total, _VALID_BAND_RATIOS[ratio_key], rel_tol=1e-6, abs_tol=1e-6
    )
    if not _num_equal(total, tc.expected) or not ratio_ok:
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^band({tc.column}, ratio={ratio_key!r}) mismatch: total={total}, share={first_band}",
        )


def _check_v2_quota(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    extracted = _extract_pct_series(table, tc, 22.5, "quota", path, findings)
    if extracted is None:
        return
    total, pct = extracted
    projected = project_quota_population(total, quota_pct=pct)
    if not math.isclose(projected, float(tc.expected), rel_tol=1e-6, abs_tol=1.0):
        _add_finding(
            findings,
            "QLAW_08_BALANCE_BOUNDS",
            path,
            f"^quota({tc.column}, pct={pct})={tc.expected} != projected {projected:.2f}",
        )


def _check_v2_top_cord(
    table: QuipuTable, tc: TopCordSpec, path: str, findings: list[dict[str, str]]
) -> None:
    if tc.kind == "sum" and tc.start_row is not None:
        _check_v2_slice_sum(table, tc, path, findings)
    elif tc.kind == "tol":
        _check_v2_tol(table, tc, path, findings)
    elif tc.kind in ("net", "equal_sum"):
        _check_v2_net(table, tc, path, findings)
    elif tc.kind == "band":
        _check_v2_band(table, tc, path, findings)
    elif tc.kind == "quota":
        _check_v2_quota(table, tc, path, findings)


def _check_v2_table_meta(
    table: QuipuTable, path: str, doc: QuipuDocument, findings: list[dict[str, str]]
) -> None:
    if doc.version != QUIPU_V2:
        return
    if table.layout is not None and table.layout not in _VALID_LAYOUTS:
        _add_finding(
            findings, "QLAW_09_ACYCLIC_SUM_DAG", path, f"Invalid @table layout {table.layout!r}"
        )
    out_of_range = any(idx < 0 or idx > len(table.rows) for idx in table.spacer_indices)
    if out_of_range or table.spacer_indices != sorted(table.spacer_indices):
        _add_finding(
            findings,
            "QLAW_09_ACYCLIC_SUM_DAG",
            path,
            f"Unsorted or out-of-range spacer indices {table.spacer_indices}",
        )
    if doc.admin_tier == AdminTier.WORKING and len(table.rows) >= MAX_WORKING_ROWS:
        _add_finding(
            findings,
            "QLAW_10_HEADER_TIER_AND_LINEAGE",
            path,
            f"Working table row count {len(table.rows)} reaches working cap "
            f"{MAX_WORKING_ROWS}; distill to summary",
        )


def _validate_table(
    table: QuipuTable, path: str, doc: QuipuDocument, findings: list[dict[str, str]]
) -> None:
    col_count = len(table.columns)
    for r_idx, row in enumerate(table.rows):
        if len(row) != col_count:
            _add_finding(
                findings,
                "QLAW_03_COLUMN_TYPES",
                f"{path}[{r_idx}]",
                f"Row arity {len(row)} != expected {col_count}",
            )
            continue
        for (col_name, col_type), cell in zip(table.columns, row, strict=True):
            if not _cell_matches_type(cell, col_type):
                _add_finding(
                    findings,
                    "QLAW_03_COLUMN_TYPES",
                    f"{path}[{r_idx}].{col_name}",
                    f"Value {cell!r} violates declared column type {col_type}",
                )
    for tc in table.top_cords:
        _check_v1_top_cord(table, tc, path, findings)
        if doc.version == QUIPU_V2:
            _check_v2_top_cord(table, tc, path, findings)
    _check_v2_table_meta(table, path, doc, findings)


def _validate_node_v2_meta(
    node: QuipuNode, path: str, doc: QuipuDocument, findings: list[dict[str, str]]
) -> None:
    if doc.version != QUIPU_V2:
        return
    for label, tag in (("unit", node.meta.unit), ("wrap", node.meta.wrap)):
        if tag is not None and not _SAFE_TAG_RE.match(tag):
            _add_finding(
                findings, "QLAW_10_HEADER_TIER_AND_LINEAGE", path, f"Unsafe node ^{label}={tag!r}"
            )
    nether = node.meta.nether
    if nether is not None and isinstance(nether, float) and not math.isfinite(nether):
        _add_finding(findings, "QLAW_08_BALANCE_BOUNDS", path, "Non-finite ^nether modifier")


def _validate_node_knots(node: QuipuNode, path: str, findings: list[dict[str, str]]) -> None:
    if node.meta.knots is None:
        return
    try:
        k_val = decode_incan_knots(node.meta.knots)
        if isinstance(node.value, int) and not isinstance(node.value, bool) and k_val != node.value:
            _add_finding(
                findings,
                "QLAW_02_TOP_CORD_ARITHMETIC",
                path,
                f"Knot ^knots={node.meta.knots!r} ({k_val}) disagrees with "
                f"integer value {node.value}",
            )
    except ValueError as exc:
        _add_finding(findings, "QLAW_02_TOP_CORD_ARITHMETIC", path, str(exc))


def _record_anchor(
    node: QuipuNode,
    path: str,
    eff_tier: CordTier,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    findings: list[dict[str, str]],
) -> None:
    if node.meta.anchor is None:
        return
    if node.meta.anchor in anchors:
        _add_finding(
            findings, "QLAW_04_ACYCLIC_ALIASES", path, f"Duplicate anchor name &{node.meta.anchor}"
        )
    else:
        anchors[node.meta.anchor] = (node, eff_tier, path)


def _walk_node_value(
    val: Any,
    path: str,
    depth: int,
    next_in_z: bool,
    eff_tier: CordTier,
    doc: QuipuDocument,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    counts: list[int],
    findings: list[dict[str, str]],
) -> None:
    if isinstance(val, float) and not math.isfinite(val):
        _add_finding(findings, "QLAW_07_SAFETY_BOUNDS", path, f"Non-finite float {val!r} rejected")
    elif isinstance(val, QuipuTable):
        counts[1] += 1
        _validate_table(val, path, doc, findings)
    elif isinstance(val, list):
        for idx, child in enumerate(val):
            _walk_node_step(
                child,
                f"{path}[{idx}]",
                depth + 1,
                next_in_z,
                eff_tier,
                doc,
                anchors,
                counts,
                findings,
            )
    elif isinstance(val, dict):
        for k, child in val.items():
            _walk_node_step(
                child,
                f"{path}.{k}",
                depth + 1,
                next_in_z,
                eff_tier,
                doc,
                anchors,
                counts,
                findings,
            )


def _effective_tier(node_tier: CordTier, inherited_tier: CordTier) -> CordTier:
    return node_tier if tier_rank(node_tier) >= tier_rank(inherited_tier) else inherited_tier


def _walk_node_step(
    node: QuipuNode,
    path: str,
    depth: int,
    in_explicit_z: bool,
    inherited_tier: CordTier,
    doc: QuipuDocument,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    counts: list[int],
    findings: list[dict[str, str]],
) -> None:
    counts[0] += 1
    if depth > MAX_QUIPU_DEPTH:
        _add_finding(
            findings,
            "QLAW_07_SAFETY_BOUNDS",
            path,
            f"Nesting depth {depth} exceeds MAX_QUIPU_DEPTH ({MAX_QUIPU_DEPTH})",
        )
        return
    eff_tier = _effective_tier(node.meta.tier, inherited_tier)
    if in_explicit_z and node.meta.explicit_spin and node.meta.spin == CordSpin.S:
        _add_finding(
            findings,
            "QLAW_05_SPIN_CONTAINMENT",
            path,
            "Mutable ~S cord forbidden inside explicit immutable ~Z container",
        )
    _record_anchor(node, path, eff_tier, anchors, findings)
    _validate_node_knots(node, path, findings)
    _validate_node_v2_meta(node, path, doc, findings)
    next_in_z = in_explicit_z or (node.meta.explicit_spin and node.meta.spin == CordSpin.Z)
    _walk_node_value(node.value, path, depth, next_in_z, eff_tier, doc, anchors, counts, findings)


def _walk_document(
    doc: QuipuDocument,
    findings: list[dict[str, str]],
) -> tuple[dict[str, tuple[QuipuNode, CordTier, str]], int, int]:
    anchors: dict[str, tuple[QuipuNode, CordTier, str]] = {}
    counts = [0, 0]
    _walk_node_step(doc.root, "$", 0, False, CordTier.T0, doc, anchors, counts, findings)
    return anchors, counts[0], counts[1]


def _resolve_alias_step(
    alias_val: CordAlias,
    path: str,
    eff_tier: CordTier,
    active: set[str],
    alias_depth: int,
    doc: QuipuDocument,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    expansions: list[int],
    findings: list[dict[str, str]],
) -> None:
    if alias_val.target not in anchors:
        _add_finding(
            findings, "QLAW_04_ACYCLIC_ALIASES", path, f"Unresolved alias *{alias_val.target}"
        )
        return
    t_node, t_tier, _ = anchors[alias_val.target]
    if tier_rank(eff_tier) <= 1 and tier_rank(t_tier) >= 2:
        _add_finding(
            findings,
            "QLAW_06_TAINT_NON_ESCALATION",
            path,
            f"Trusted {eff_tier.value} cord cannot alias untrusted "
            f"{t_tier.value} anchor &{alias_val.target}",
        )
    if alias_val.target in active:
        _add_finding(
            findings,
            "QLAW_04_ACYCLIC_ALIASES",
            path,
            f"Cyclic alias chain detected at *{alias_val.target}",
        )
        return
    if doc.version == QUIPU_V2 and alias_depth + 1 > MAX_COMPOUND_SUM_DEPTH:
        _add_finding(
            findings,
            "QLAW_09_ACYCLIC_SUM_DAG",
            path,
            f"Compound DAG alias depth {alias_depth + 1} exceeds {MAX_COMPOUND_SUM_DEPTH}",
        )
        return
    expansions[0] += 1
    if expansions[0] > MAX_ALIAS_EXPANSIONS:
        _add_finding(
            findings,
            "QLAW_04_ACYCLIC_ALIASES",
            path,
            f"Alias expansions exceeded {MAX_ALIAS_EXPANSIONS} (anti-CWE-776 bound)",
        )
        return
    _visit_alias_node(
        t_node,
        f"{path}->*{alias_val.target}",
        eff_tier,
        active | {alias_val.target},
        alias_depth + 1,
        doc,
        anchors,
        expansions,
        findings,
    )


def _visit_alias_node(
    node: QuipuNode,
    path: str,
    inherited_tier: CordTier,
    active: set[str],
    alias_depth: int,
    doc: QuipuDocument,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    expansions: list[int],
    findings: list[dict[str, str]],
) -> None:
    eff_tier = _effective_tier(node.meta.tier, inherited_tier)
    val = node.value
    if isinstance(val, CordAlias):
        _resolve_alias_step(
            val, path, eff_tier, active, alias_depth, doc, anchors, expansions, findings
        )
    elif isinstance(val, list):
        for idx, child in enumerate(val):
            _visit_alias_node(
                child,
                f"{path}[{idx}]",
                eff_tier,
                active,
                alias_depth,
                doc,
                anchors,
                expansions,
                findings,
            )
    elif isinstance(val, dict):
        for k, child in val.items():
            _visit_alias_node(
                child,
                f"{path}.{k}",
                eff_tier,
                active,
                alias_depth,
                doc,
                anchors,
                expansions,
                findings,
            )


def _check_aliases_graph(
    doc: QuipuDocument,
    anchors: dict[str, tuple[QuipuNode, CordTier, str]],
    findings: list[dict[str, str]],
) -> int:
    expansions = [0]
    _visit_alias_node(doc.root, "$", CordTier.T0, set(), 0, doc, anchors, expansions, findings)
    return expansions[0]


def _syntax_error_report(exc: QuipuSyntaxError) -> dict[str, Any]:
    msg = str(exc)
    safety_markers = (
        "Maximum nesting depth",
        "MAX_QUIPU_DEPTH",
        "MAX_QUIPU_BYTES",
        "Non-finite float",
        "Null byte",
    )
    is_safety = any(m in msg for m in safety_markers)
    law = "QLAW_07_SAFETY_BOUNDS" if is_safety else "QLAW_00_SYNTAX"
    return {
        "valid": False,
        "verdict": "SAFETY_VIOLATION" if is_safety else "SYNTAX_ERROR",
        "findings_count": 1,
        "findings": [{"law": law, "path": "$", "severity": "error", "message": msg}],
        "laws_checked": ["QLAW_07_SAFETY_BOUNDS"] if is_safety else [],
    }


def verify_quipu(
    doc_or_text: QuipuDocument | str, *, require_seal: bool | None = None
) -> dict[str, Any]:
    """Runs static verification laws (7 for QUIPU/1.0, 10 for QUIPU/2.0) and returns verdict."""
    if isinstance(doc_or_text, str):
        if "\x00" in doc_or_text:
            return _syntax_error_report(QuipuSyntaxError("Null byte rejected in QUIPU payload"))
        try:
            doc = parse_quipu(doc_or_text)
        except QuipuSyntaxError as exc:
            return _syntax_error_report(exc)
    else:
        doc = doc_or_text

    findings: list[dict[str, str]] = []
    laws_checked = _V1_LAWS + (_V2_LAWS if doc.version == QUIPU_V2 else [])
    _check_seal(doc, require_seal, findings)
    _check_v2_header_and_tags(doc, findings)
    anchors, cords_count, tables_count = _walk_document(doc, findings)
    alias_expansions = _check_aliases_graph(doc, anchors, findings)
    valid = len(findings) == 0
    return {
        "valid": valid,
        "verdict": "VERIFIED" if valid else "VIOLATION",
        "version": doc.version,
        "doc_id": doc.doc_id,
        "mode": doc.mode.value,
        "knot": doc.seal.knot if doc.seal else None,
        "findings_count": len(findings),
        "findings": findings,
        "laws_checked": laws_checked,
        "stats": {
            "cords": cords_count,
            "tables": tables_count,
            "anchors": len(anchors),
            "alias_expansions": alias_expansions,
        },
    }


def benchmark_quipu_vs_json(data: Any) -> dict[str, Any]:
    """Measures byte and estimated token efficiency of QUIPU vs JSON (pretty & compact)."""
    json_pretty = json.dumps(data, indent=2, ensure_ascii=False)
    json_compact = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    quipu_lax = dumps_quipu(data, mode="lax", include_header=False)
    quipu_sealed = dumps_quipu(data, mode="sealed", include_header=True)
    pretty_chars = max(1, len(json_pretty))
    lax_chars = len(quipu_lax)
    sealed_chars = len(quipu_sealed)
    savings_pretty = round((1.0 - (lax_chars / pretty_chars)) * 100.0, 2)
    savings_compact = round((1.0 - (lax_chars / max(1, len(json_compact)))) * 100.0, 2)
    roundtrip_exact = (
        dumps_quipu(data, mode="sealed") != "" and quipu_to_data(parse_quipu(quipu_sealed)) == data
    )
    return {
        "json_pretty_chars": len(json_pretty),
        "json_compact_chars": len(json_compact),
        "quipu_lax_chars": lax_chars,
        "quipu_sealed_chars": sealed_chars,
        "est_json_pretty_tokens": max(1, len(json_pretty) // 4),
        "est_quipu_lax_tokens": max(1, lax_chars // 4),
        "savings_vs_pretty_json_pct": savings_pretty,
        "savings_vs_compact_json_pct": savings_compact,
        "sealed_overhead_bytes": sealed_chars - lax_chars,
        "roundtrip_exact": roundtrip_exact,
    }


verify = verify_quipu
