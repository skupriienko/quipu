"""quipu.ast_nodes — Typed AST, Cord Spin/Attachment, Polarity & Base-10 Knots.

Standalone pure-stdlib data model for the QUIPU/2.0 & QUIPU/1.0 (.quipu)
universal AI-native structured data and provenance serialization format.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

QUIPU_V1 = "QUIPU/1.0"
QUIPU_V2 = "QUIPU/2.0"
DEFAULT_QUIPU_VERSION = QUIPU_V2
SUPPORTED_QUIPU_VERSIONS: frozenset[str] = frozenset({QUIPU_V1, QUIPU_V2})

MAX_QUIPU_BYTES = 10_485_760  # 10 MiB input safety ceiling (CWE-400)
MAX_QUIPU_DEPTH = 32  # Bounded nesting depth against stack exhaustion
MAX_ALIAS_EXPANSIONS = 1_024  # Anti-billion-laughs anchor bomb bound (CWE-776)
MAX_COMPOUND_SUM_DEPTH = 10  # Acyclic compound sum DAG depth bound
MAX_WORKING_ROWS = 1_000  # Working-tier table row ceiling before summary distillation

SCALE_BUCKETS: tuple[int, ...] = (1, 2, 3, 4, 5, 10, 15, 40, 50, 100, 500, 1000)

_KNOTS_RE = re.compile(r"^(-?)(\d+)M-(\d)C-(\d)D-(?:(\d)U|(1)E)$")

VALID_COLUMN_TYPES: frozenset[str] = frozenset(
    {"any", "str", "int", "float", "bool", "str?", "int?", "float?", "bool?"}
)


class QuipuError(Exception):
    """Base exception for all QUIPU operations."""


class QuipuSyntaxError(QuipuError):
    """Raised when parsing malformed QUIPU wire text."""

    def __init__(self, message: str, line: int = 1, col: int = 1) -> None:
        self.line = line
        self.col = col
        super().__init__(f"Line {line}, Col {col}: {message}")


class QuipuVerificationError(QuipuError):
    """Raised when a QUIPU document fails verification invariants."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        summary = "; ".join(f"{f['law']}: {f['message']}" for f in findings[:3])
        super().__init__(f"QUIPU verification failed ({len(findings)} findings): {summary}")


class CordSpin(str, Enum):
    """Twist direction semantics governing cord mutability."""

    Z = "Z"  # Right-twist: immutable / read-only cord
    S = "S"  # Left-twist: mutable / write-capable cord


class CordTier(str, Enum):
    """Provenance and taint trust hierarchy (T0 highest -> T3 untrusted)."""

    T0 = "T0"  # Authoritative / verified source of truth
    T1 = "T1"  # Trusted workspace / internal inferred
    T2 = "T2"  # Semi-trusted / external fetched source
    T3 = "T3"  # Untrusted / raw user or network payload


class CordAttachment(str, Enum):
    """Paired cord attachment side (`~R` primary / `~V` shadow)."""

    R = "R"  # Primary / outward-facing branch
    V = "V"  # Shadow / verification / inverse branch


class CordPolarity(str, Enum):
    """Double-entry accounting polarity (`@W` Credit / `@D` Debt)."""

    WHITE = "W"  # Credit / asset / planned budget / settled balance
    DARK = "D"  # Obligation / debt / granular execution charge


class AdminTier(str, Enum):
    """Granularity classification for QUIPU/2.0 documents."""

    WORKING = "working"  # Granular packet (< 1,000 rows per table)
    SUMMARY = "summary"  # High-level compacted / distilled rollup packet
    HYBRID = "hybrid"  # Mixed granular and summary planes


class QuipuMode(str, Enum):
    """Document verification strictness mode."""

    SEALED = "sealed"  # Requires valid SHA-256 knot footer
    LAX = "lax"  # Ergonomic config mode; cryptographic seal optional unless present


_TIER_RANK: dict[CordTier, int] = {
    CordTier.T0: 0,
    CordTier.T1: 1,
    CordTier.T2: 2,
    CordTier.T3: 3,
}


def _bit(flag: bool) -> str:
    return "1" if flag else "0"


def normalize_quipu_version(version: str | None) -> str:
    """Normalizes version strings ('1.0', '2.0', 'v2', 'QUIPU/2.0') to canonical headers."""
    if version is None:
        return DEFAULT_QUIPU_VERSION
    upper = str(version).strip().upper()
    if upper in (QUIPU_V2, "2.0", "2", "V2"):
        return QUIPU_V2
    if upper in (QUIPU_V1, "1.0", "1", "V1"):
        return QUIPU_V1
    raise QuipuSyntaxError(
        f"Unsupported QUIPU version {version!r}; expected 'QUIPU/1.0' or 'QUIPU/2.0'"
    )


def tier_rank(tier: CordTier) -> int:
    """Returns numeric taint rank (0=T0 cleanest, 3=T3 most untrusted)."""
    return _TIER_RANK[tier]


def encode_incan_knots(value: int, *, figure_eight_unit: bool = False) -> str:
    """Encodes an integer into positional base-10 knot notation (M-C-D-U or M-C-D-1E)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Knot encoding requires non-boolean int, got {type(value).__name__}")
    sign = "-" if value < 0 else ""
    mag = abs(value)
    thousands = mag // 1000
    hundreds = (mag % 1000) // 100
    tens = (mag % 100) // 10
    units = mag % 10
    unit_tok = "1E" if (figure_eight_unit and units == 1) else f"{units}U"
    return f"{sign}{thousands}M-{hundreds}C-{tens}D-{unit_tok}"


def decode_incan_knots(knots: str) -> int:
    """Decodes positional base-10 knot notation (M-C-D-U or M-C-D-1E) into an int."""
    m = _KNOTS_RE.match(knots.strip())
    if not m:
        raise ValueError(f"Invalid knot notation {knots!r}; expected '<M>M-<C>C-<D>D-<U>U' or '1E'")
    sign_str, m_str, c_str, d_str, u_str, e_str = m.groups()
    units_val = int(u_str) if u_str is not None else int(e_str)
    total = int(m_str) * 1000 + int(c_str) * 100 + int(d_str) * 10 + units_val
    return -total if sign_str == "-" else total


def encode_urton_7bit(
    spin: CordSpin = CordSpin.Z,
    tier: CordTier = CordTier.T0,
    *,
    has_numeric: bool = False,
    is_table: bool = False,
) -> str:
    """Encodes cord metadata into a deterministic 7-bit structural register string."""
    t_bits = {
        CordTier.T0: "00",
        CordTier.T1: "01",
        CordTier.T2: "10",
        CordTier.T3: "11",
    }[tier]
    return f"1{_bit(is_table)}{_bit(spin == CordSpin.Z)}{t_bits}{_bit(has_numeric)}1"


def encode_urton_14bit(
    meta: CordMeta,
    *,
    has_numeric: bool = False,
    is_table: bool = False,
) -> str:
    """Encodes QUIPU/2.0 cord metadata into an extended 14-bit structural register."""
    u7 = encode_urton_7bit(
        meta.spin,
        meta.tier,
        has_numeric=has_numeric,
        is_table=is_table,
    )
    bits = (
        _bit(meta.attachment is not None),
        _bit(meta.attachment == CordAttachment.R),
        _bit(meta.polarity is not None),
        _bit(meta.polarity == CordPolarity.WHITE),
        _bit(meta.unit is not None or meta.wrap is not None),
        _bit(meta.nether is not None),
        _bit(meta.anchor is not None),
    )
    return u7 + "".join(bits)


def quantize_bucket(value: int) -> int:
    """Maps a positive integer to its nearest ceiling logarithmic scale bucket (1..1000)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"Bucket quantization requires non-boolean int, got {type(value).__name__}"
        )
    if value <= 0:
        return 0
    for bucket in SCALE_BUCKETS:
        if value <= bucket:
            return bucket
    return SCALE_BUCKETS[-1]


encode_knots = encode_incan_knots
decode_knots = decode_incan_knots
encode_7bit = encode_urton_7bit
encode_14bit = encode_urton_14bit


def project_quota_population(
    observed_value: int | float,
    *,
    quota_pct: float = 22.5,
) -> float:
    """Reconstructs total cohort capacity from a fixed-percentage quota cord."""
    if isinstance(observed_value, bool) or not isinstance(observed_value, (int, float)):
        raise ValueError("observed_value must be finite int or float")
    if isinstance(quota_pct, bool) or not isinstance(quota_pct, (int, float)):
        raise ValueError("quota_pct must be finite int or float")
    obs_f = float(observed_value)
    pct_f = float(quota_pct)
    if not math.isfinite(obs_f) or not math.isfinite(pct_f):
        raise ValueError("observed_value and quota_pct must be finite")
    if pct_f <= 0.0 or pct_f > 100.0:
        raise ValueError(f"quota_pct must be in (0, 100], got {pct_f}")
    return obs_f / (pct_f / 100.0)


@dataclass(frozen=True, slots=True)
class CordMeta:
    """Inline provenance, spin, branch side, polarity, anchor, wrap, and knot metadata."""

    spin: CordSpin = CordSpin.Z
    tier: CordTier = CordTier.T0
    anchor: str | None = None
    knots: str | None = None
    explicit_spin: bool = False
    explicit_tier: bool = False
    attachment: CordAttachment | None = None
    polarity: CordPolarity | None = None
    unit: str | None = None
    wrap: str | None = None
    nether: int | float | None = None

    def has_v2_annotations(self) -> bool:
        return any(
            x is not None
            for x in (self.attachment, self.polarity, self.unit, self.wrap, self.nether)
        )

    def has_annotations(self) -> bool:
        return (
            self.anchor is not None
            or self.explicit_spin
            or self.spin != CordSpin.Z
            or self.explicit_tier
            or self.tier != CordTier.T0
            or self.knots is not None
            or self.has_v2_annotations()
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "spin": self.spin.value,
            "tier": self.tier.value,
            "anchor": self.anchor,
            "knots": self.knots,
            "explicit_spin": self.explicit_spin,
            "explicit_tier": self.explicit_tier,
        }
        if self.attachment is not None:
            data["attachment"] = self.attachment.value
        if self.polarity is not None:
            data["polarity"] = self.polarity.value
        if self.unit is not None:
            data["unit"] = self.unit
        if self.wrap is not None:
            data["wrap"] = self.wrap
        if self.nether is not None:
            data["nether"] = self.nether
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> CordMeta:
        if not data:
            return cls()
        att_raw = data.get("attachment")
        pol_raw = data.get("polarity")
        return cls(
            spin=CordSpin(str(data.get("spin", "Z"))),
            tier=CordTier(str(data.get("tier", "T0"))),
            anchor=data.get("anchor"),
            knots=data.get("knots"),
            explicit_spin=bool(data.get("explicit_spin", False)),
            explicit_tier=bool(data.get("explicit_tier", False)),
            attachment=CordAttachment(str(att_raw)) if att_raw else None,
            polarity=CordPolarity(str(pol_raw)) if pol_raw else None,
            unit=str(data["unit"]) if data.get("unit") is not None else None,
            wrap=str(data["wrap"]) if data.get("wrap") is not None else None,
            nether=data.get("nether"),
        )


@dataclass(frozen=True, slots=True)
class CordAlias:
    """Bounded DAG alias referencing an earlier `&anchor` declaration."""

    target: str

    def to_dict(self) -> dict[str, Any]:
        return {"alias": self.target}


@dataclass(frozen=True, slots=True)
class TopCordSpec:
    """Columnar reconciliation directive (`count`, `sum`, `tol`, `net`, `equal_sum`, `band`)."""

    kind: str
    column: str | None
    expected: int | float
    end_column: str | None = None
    start_row: int | None = None
    end_row: int | None = None
    tolerance_pct: float | None = None
    ratio: str | None = None

    def is_v2(self) -> bool:
        return self.kind not in ("count", "sum") or (
            self.start_row is not None or self.end_row is not None
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "column": self.column,
            "expected": self.expected,
        }
        for key in ("end_column", "start_row", "end_row", "tolerance_pct", "ratio"):
            attr_val = getattr(self, key)
            if attr_val is not None:
                out[key] = attr_val
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopCordSpec:
        return cls(
            kind=str(data["kind"]),
            column=data.get("column"),
            expected=data["expected"],
            end_column=data.get("end_column"),
            start_row=data.get("start_row"),
            end_row=data.get("end_row"),
            tolerance_pct=data.get("tolerance_pct"),
            ratio=data.get("ratio"),
        )


def _infer_column_type(values: list[Any]) -> str:
    has_none = any(v is None for v in values)
    non_none = [v for v in values if v is not None]
    if not non_none:
        return "any"
    types = {type(v) for v in non_none}
    if len(types) != 1:
        return "any"
    only_type = next(iter(types))
    suffix = "?" if has_none else ""
    type_map: dict[type[Any], str] = {
        bool: "bool",
        int: "int",
        float: "float",
        str: "str",
    }
    base = type_map.get(only_type)
    return f"{base}{suffix}" if base is not None else "any"


def is_valid_scalar_for_table(val: Any) -> bool:
    if val is None or isinstance(val, (bool, int, str)):
        return True
    if isinstance(val, float):
        return math.isfinite(val)
    return False


@dataclass(slots=True)
class QuipuTable:
    """Typed columnar table eliminating JSON key repetition with Top-Cord reconciliation."""

    columns: list[tuple[str, str]]
    rows: list[list[Any]] = field(default_factory=list)
    top_cords: list[TopCordSpec] = field(default_factory=list)
    spacer_indices: list[int] = field(default_factory=list)
    layout: str | None = None

    def has_v2_features(self) -> bool:
        return (
            bool(self.spacer_indices)
            or self.layout is not None
            or any(tc.is_v2() for tc in self.top_cords)
        )

    def column_index(self, col_name: str) -> int | None:
        for idx, (name, _ctype) in enumerate(self.columns):
            if name == col_name:
                return idx
        return None

    def to_records(self) -> list[dict[str, Any]]:
        """Decodes table rows back into standard list[dict] records."""
        col_names = [name for name, _ctype in self.columns]
        return [dict(zip(col_names, row, strict=True)) for row in self.rows]

    @classmethod
    def from_records(
        cls,
        records: list[dict[str, Any]],
        *,
        auto_top_cords: bool = True,
        max_sum_cols: int = 3,
    ) -> QuipuTable:
        """Compiles homogeneous scalar dicts into a typed columnar QuipuTable."""
        if not records:
            raise ValueError("Cannot infer table columns from empty record list")
        first_keys = list(records[0].keys())
        columns = [
            (col_name, _infer_column_type([rec[col_name] for rec in records]))
            for col_name in first_keys
        ]
        rows = [[rec[name] for name, _ctype in columns] for rec in records]
        top_cords: list[TopCordSpec] = []
        if auto_top_cords:
            top_cords.append(TopCordSpec(kind="count", column=None, expected=len(rows)))
            summed = 0
            for idx, (name, ctype) in enumerate(columns):
                if ctype == "int" and summed < max_sum_cols:
                    col_sum = sum(int(row[idx]) for row in rows)
                    top_cords.append(TopCordSpec(kind="sum", column=name, expected=col_sum))
                    summed += 1
        return cls(columns=columns, rows=rows, top_cords=top_cords)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "columns": [{"name": n, "type": t} for n, t in self.columns],
            "rows": [list(r) for r in self.rows],
            "top_cords": [tc.to_dict() for tc in self.top_cords],
        }
        if self.spacer_indices:
            out["spacer_indices"] = list(self.spacer_indices)
        if self.layout is not None:
            out["layout"] = self.layout
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuipuTable:
        cols = [(str(c["name"]), str(c["type"])) for c in data.get("columns", [])]
        rows = [list(r) for r in data.get("rows", [])]
        tcs = [TopCordSpec.from_dict(tc) for tc in data.get("top_cords", [])]
        spacers = [int(i) for i in data.get("spacer_indices", [])]
        layout = str(data["layout"]) if data.get("layout") is not None else None
        return cls(
            columns=cols,
            rows=rows,
            top_cords=tcs,
            spacer_indices=spacers,
            layout=layout,
        )


@dataclass(slots=True)
class QuipuNode:
    """AST node wrapping any scalar, list, map, QuipuTable, or CordAlias."""

    value: Any
    meta: CordMeta = field(default_factory=CordMeta)

    def to_dict(self) -> dict[str, Any]:
        val = self.value
        if isinstance(val, QuipuTable):
            ser_val: Any = {"__quipu_table__": val.to_dict()}
        elif isinstance(val, CordAlias):
            ser_val = {"__quipu_alias__": val.target}
        elif isinstance(val, list):
            ser_val = [item.to_dict() for item in val]
        elif isinstance(val, dict):
            ser_val = {k: v.to_dict() for k, v in val.items()}
        else:
            ser_val = val
        return {"value": ser_val, "meta": self.meta.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuipuNode:
        meta = CordMeta.from_dict(data.get("meta"))
        raw_val = data.get("value")
        if isinstance(raw_val, dict):
            if "__quipu_table__" in raw_val:
                val: Any = QuipuTable.from_dict(raw_val["__quipu_table__"])
            elif "__quipu_alias__" in raw_val:
                val = CordAlias(target=str(raw_val["__quipu_alias__"]))
            else:
                val = {k: cls.from_dict(v) for k, v in raw_val.items()}
        elif isinstance(raw_val, list):
            val = [cls.from_dict(v) for v in raw_val]
        else:
            val = raw_val
        return cls(value=val, meta=meta)


@dataclass(frozen=True, slots=True)
class QuipuSeal:
    """Trailing cryptographic SHA-256 seal on a QUIPU document."""

    knot: str
    sha256: str
    reconciled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"knot": self.knot, "sha256": self.sha256, "reconciled": self.reconciled}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuipuSeal:
        return cls(
            knot=str(data["knot"]),
            sha256=str(data["sha256"]),
            reconciled=bool(data.get("reconciled", True)),
        )


@dataclass(slots=True)
class QuipuDocument:
    """Root AST container for a complete QUIPU/1.0 or QUIPU/2.0 document."""

    doc_id: str = "root"
    mode: QuipuMode = QuipuMode.SEALED
    version: str = DEFAULT_QUIPU_VERSION
    root: QuipuNode = field(default_factory=lambda: QuipuNode(value={}))
    seal: QuipuSeal | None = None
    admin_tier: AdminTier | None = None
    tag: str | None = None
    parent: str | None = None
    hub: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": self.version,
            "doc_id": self.doc_id,
            "mode": self.mode.value,
            "root": self.root.to_dict(),
            "seal": self.seal.to_dict() if self.seal else None,
        }
        v2_headers = {
            "admin_tier": self.admin_tier.value if self.admin_tier is not None else None,
            "tag": self.tag,
            "parent": self.parent,
            "hub": self.hub,
        }
        out.update({k: v for k, v in v2_headers.items() if v is not None})
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuipuDocument:
        seal_raw = data.get("seal")
        tier_raw = data.get("admin_tier")
        root_node = QuipuNode.from_dict(data["root"]) if "root" in data else QuipuNode(value={})
        return cls(
            doc_id=str(data.get("doc_id", "root")),
            mode=QuipuMode(str(data.get("mode", "sealed"))),
            version=normalize_quipu_version(data.get("version", QUIPU_V1)),
            root=root_node,
            seal=QuipuSeal.from_dict(seal_raw) if isinstance(seal_raw, dict) else None,
            admin_tier=AdminTier(str(tier_raw)) if tier_raw else None,
            tag=str(data["tag"]) if data.get("tag") is not None else None,
            parent=str(data["parent"]) if data.get("parent") is not None else None,
            hub=str(data["hub"]) if data.get("hub") is not None else None,
        )
