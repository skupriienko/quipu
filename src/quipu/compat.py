"""quipu.compat — QUIPU/1.0 <-> QUIPU/2.0 Compatibility Shims, Distillation & Federation.

Provides lossless upgrade and downgrade paths so QUIPU/2.0 transparently ingests
QUIPU/1.0 artifacts and exports clean QUIPU/1.0 wire documents for legacy consumers,
plus working-to-summary distillation and multi-packet hub linking.
"""

from __future__ import annotations

from typing import Any

from .ast_nodes import (
    QUIPU_V1,
    QUIPU_V2,
    AdminTier,
    CordMeta,
    CordSpin,
    CordTier,
    QuipuDocument,
    QuipuMode,
    QuipuNode,
    QuipuTable,
    TopCordSpec,
    normalize_quipu_version,
)
from .codec import compute_quipu_seal, parse_quipu, sample_quipu, serialize_quipu_body
from .verifier import verify_quipu


def sample_quipu_v1() -> str:
    """Returns a canonical verified QUIPU/1.0 sample document."""
    return sample_quipu(version=QUIPU_V1)


def detect_quipu_version(doc_or_text: QuipuDocument | str) -> str:
    """Returns canonical version ('QUIPU/1.0' or 'QUIPU/2.0') of a document or wire string."""
    doc = parse_quipu(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    return normalize_quipu_version(doc.version)


def is_quipu_v1(doc_or_text: QuipuDocument | str) -> bool:
    """Returns True if the given document or wire text is QUIPU/1.0."""
    return detect_quipu_version(doc_or_text) == QUIPU_V1


def is_quipu_v2(doc_or_text: QuipuDocument | str) -> bool:
    """Returns True if the given document or wire text is QUIPU/2.0."""
    return detect_quipu_version(doc_or_text) == QUIPU_V2


def _clone_table(table: QuipuTable, *, strip_v2: bool) -> QuipuTable:
    tcs = [
        TopCordSpec.from_dict(tc.to_dict())
        for tc in table.top_cords
        if not (strip_v2 and tc.is_v2())
    ]
    return QuipuTable(
        columns=list(table.columns),
        rows=[list(r) for r in table.rows],
        top_cords=tcs,
        spacer_indices=[] if strip_v2 else list(table.spacer_indices),
        layout=None if strip_v2 else table.layout,
    )


def _clone_node(node: QuipuNode, *, strip_v2: bool) -> QuipuNode:
    src_m = node.meta
    meta = CordMeta(
        spin=src_m.spin,
        tier=src_m.tier,
        anchor=src_m.anchor,
        knots=src_m.knots,
        explicit_spin=src_m.explicit_spin,
        explicit_tier=src_m.explicit_tier,
        attachment=None if strip_v2 else src_m.attachment,
        polarity=None if strip_v2 else src_m.polarity,
        unit=None if strip_v2 else src_m.unit,
        wrap=None if strip_v2 else src_m.wrap,
        nether=None if strip_v2 else src_m.nether,
    )
    val = node.value
    if isinstance(val, QuipuTable):
        return QuipuNode(value=_clone_table(val, strip_v2=strip_v2), meta=meta)
    if isinstance(val, list):
        return QuipuNode(value=[_clone_node(child, strip_v2=strip_v2) for child in val], meta=meta)
    if isinstance(val, dict):
        return QuipuNode(
            value={k: _clone_node(child, strip_v2=strip_v2) for k, child in val.items()},
            meta=meta,
        )
    return QuipuNode(value=val, meta=meta)


def upgrade_quipu_to_v2(
    doc_or_text: QuipuDocument | str,
    *,
    admin_tier: str | None = None,
    tag: str | None = None,
    hub: str | None = None,
    recompute_seal: bool = True,
) -> QuipuDocument:
    """Upgrades a QUIPU/1.0 (or QUIPU/2.0) document to QUIPU/2.0 with parent lineage."""
    src = parse_quipu(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    src_knot = (
        src.seal.knot
        if src.seal
        else compute_quipu_seal(serialize_quipu_body(src, include_header=True)).knot
    )
    resolved_tier = AdminTier(admin_tier) if admin_tier is not None else src.admin_tier
    upgraded = QuipuDocument(
        doc_id=src.doc_id,
        mode=src.mode,
        version=QUIPU_V2,
        root=_clone_node(src.root, strip_v2=False),
        seal=None,
        admin_tier=resolved_tier,
        tag=tag if tag is not None else src.tag,
        parent=src.parent or src_knot,
        hub=hub if hub is not None else src.hub,
    )
    if recompute_seal or upgraded.mode == QuipuMode.SEALED:
        upgraded.seal = compute_quipu_seal(serialize_quipu_body(upgraded, include_header=True))
    return upgraded


def downgrade_quipu_to_v1(
    doc_or_text: QuipuDocument | str,
    *,
    recompute_seal: bool = True,
) -> QuipuDocument:
    """Downgrades a QUIPU/2.0 document to strictly compliant 7-law QUIPU/1.0."""
    src = parse_quipu(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    downgraded = QuipuDocument(
        doc_id=src.doc_id,
        mode=src.mode,
        version=QUIPU_V1,
        root=_clone_node(src.root, strip_v2=True),
        seal=None,
    )
    if recompute_seal or downgraded.mode == QuipuMode.SEALED:
        downgraded.seal = compute_quipu_seal(serialize_quipu_body(downgraded, include_header=True))
    return downgraded


def _summarize_table_node(table: QuipuTable) -> dict[str, QuipuNode]:
    col_sums: dict[str, QuipuNode] = {}
    for idx, (col_name, ctype) in enumerate(table.columns):
        if ctype.rstrip("?") in ("int", "float"):
            vals = [
                r[idx]
                for r in table.rows
                if idx < len(r)
                and isinstance(r[idx], (int, float))
                and not isinstance(r[idx], bool)
            ]
            col_sums[col_name] = QuipuNode(value=sum(vals))
    return {
        "row_count": QuipuNode(value=len(table.rows)),
        "column_count": QuipuNode(value=len(table.columns)),
        "band_count": QuipuNode(value=len(table.spacer_indices) + 1 if table.rows else 0),
        "numeric_sums": QuipuNode(value=col_sums),
    }


def _distill_node(node: QuipuNode) -> QuipuNode:
    val = node.value
    if isinstance(val, QuipuTable):
        return QuipuNode(value=_summarize_table_node(val), meta=node.meta)
    if isinstance(val, list):
        return QuipuNode(value=[_distill_node(child) for child in val], meta=node.meta)
    if isinstance(val, dict):
        return QuipuNode(
            value={k: _distill_node(child) for k, child in val.items()}, meta=node.meta
        )
    return _clone_node(node, strip_v2=False)


def distill_working_to_summary(
    doc_or_text: QuipuDocument | str,
    *,
    doc_id: str | None = None,
) -> QuipuDocument:
    """Compacts a working QUIPU document into a summary QUIPU/2.0 packet with parent lineage."""
    src = parse_quipu(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    src_knot = (
        src.seal.knot
        if src.seal
        else compute_quipu_seal(serialize_quipu_body(src, include_header=True)).knot
    )
    summary_doc = QuipuDocument(
        doc_id=doc_id or f"{src.doc_id}.summary",
        mode=QuipuMode.SEALED,
        version=QUIPU_V2,
        root=_distill_node(src.root),
        admin_tier=AdminTier.SUMMARY,
        tag=src.tag,
        parent=src_knot,
        hub=src.hub,
    )
    summary_doc.seal = compute_quipu_seal(serialize_quipu_body(summary_doc, include_header=True))
    return summary_doc


def link_quipus(
    packets: dict[str, QuipuDocument | str],
    *,
    hub_id: str = "HubA",
    doc_id: str = "quipu.linked.bundle",
) -> QuipuDocument:
    """Links multiple QUIPU/1.0 and QUIPU/2.0 packets into one federated hub manifest."""
    if not packets:
        raise ValueError("link_quipus requires at least one member packet")
    member_rows: list[list[Any]] = []
    for slot_name, pkt in sorted(packets.items()):
        parsed = parse_quipu(pkt) if isinstance(pkt, str) else pkt
        rep = verify_quipu(parsed, require_seal=False)
        stats = rep.get("stats", {})
        row_total = sum(
            len(n.value.rows)
            for n in (parsed.root.value.values() if isinstance(parsed.root.value, dict) else [])
            if isinstance(n, QuipuNode) and isinstance(n.value, QuipuTable)
        )
        member_rows.append(
            [
                str(slot_name),
                parsed.doc_id,
                parsed.version,
                parsed.mode.value,
                str(rep.get("knot") or "unsealed"),
                int(stats.get("cords", 0)),
                int(row_total),
            ]
        )
    members_table = QuipuTable(
        columns=[
            ("slot", "str"),
            ("doc_id", "str"),
            ("version", "str"),
            ("mode", "str"),
            ("knot", "str"),
            ("cords", "int"),
            ("rows", "int"),
        ],
        rows=member_rows,
        top_cords=[
            TopCordSpec(kind="count", column=None, expected=len(member_rows)),
            TopCordSpec(kind="sum", column="cords", expected=sum(r[5] for r in member_rows)),
            TopCordSpec(kind="sum", column="rows", expected=sum(r[6] for r in member_rows)),
        ],
        layout="banded",
    )
    bundle = QuipuDocument(
        doc_id=doc_id,
        mode=QuipuMode.SEALED,
        version=QUIPU_V2,
        admin_tier=AdminTier.SUMMARY,
        tag="linked_hub",
        hub=hub_id,
        root=QuipuNode(
            value={
                "hub_id": QuipuNode(value=hub_id, meta=CordMeta(spin=CordSpin.Z, tier=CordTier.T0)),
                "members": QuipuNode(
                    value=members_table, meta=CordMeta(spin=CordSpin.Z, tier=CordTier.T0)
                ),
            }
        ),
    )
    bundle.seal = compute_quipu_seal(serialize_quipu_body(bundle, include_header=True))
    return bundle
