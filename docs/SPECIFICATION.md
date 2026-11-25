# QUIPU/2.0 & QUIPU/1.0 Format Specification

- **Document Class**: Technical Protocol Specification
- **Protocol Versions**: `QUIPU/2.0` (Default), `QUIPU/1.0` (Legacy Compatible)
- **Media Type**: `application/quipu`
- **File Extension**: `.quipu`
- **Character Encoding**: UTF-8 (NUL `\x00` strictly forbidden)
- **Default Wire Header**: `~= QUIPU/2.0 id="<doc_id>" mode=sealed`

---

## 1. Abstract & Conformance

This specification defines the syntax, lexical rules, canonical serialization, cryptographic SHA-256 sealing algorithm, typed AST model, backward-compatibility rules, and 10 static verification laws (`QLAW_01`..`QLAW_10`) of the **QUIPU** (`.quipu`) structured data and provenance format.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, and **MAY** in this document are to be interpreted as described in RFC 2119.

### 1.1 Design Goals

1. **100% Lossless JSON Bijection**: Any JSON-compatible data tree (`null`, `bool`, `int`, finite `float`, `str`, `list`, `dict`) round-trips through `dumps()` and `loads()` without type loss or ambiguity (`bool` is strictly distinct from `int`).
2. **Columnar Efficiency**: Uniform record lists compile into typed `@table(...)` grids, eliminating key repetition and validating per-column cell types statically.
3. **Inline Static Verification**: Upward Top-Cord assertions (`^count`, `^sum`, slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota`) verify arithmetic, double-entry conservation, and bounds prior to business logic.
4. **Out-of-Band Governance Metadata**: Cord decorators (`~Z`/`~S`, `~R`/`~V`, `@T0..@T3`, `@W`/`@D`, `^unit`, `^wrap`, `^nether`, `^knots`, `&anchor`/`*alias`) attach mutability, branch role, trust tier, accounting polarity, and parity metadata without wrapping or altering decoded JSON values.
5. **Cryptographic Tamper Evidence**: `mode=sealed` documents carry a deterministic SHA-256 Merkle knot footer (`=~ knot="quipu-<12hex>" sha256="<64hex>" reconciled=true`).

---

## 2. Lexical Grammar & Escaping Rules

A QUIPU payload is a valid UTF-8 text stream not exceeding `MAX_QUIPU_BYTES` (`10_485_760` bytes / 10 MiB) and containing zero NUL (`\x00`) bytes.

### 2.1 Whitespace & Comments

- Horizontal whitespace (`' '`, `'\t'`, `'\r'`) separates tokens and is ignored outside string literals.
- Line comments begin with `#` outside string literals and continue until the next `\n` or `EOF`.
- Newlines (`'\n'`) terminate headers, seals, implicit root entries, and `@table` rows.

### 2.2 Lexical Tokens

| Token | Pattern / Definition | Notes |
| :--- | :--- | :--- |
| `HEADER_OP` | `~=` | Opens protocol header line |
| `SEAL_OP` | `=~` | Opens trailing SHA-256 reconciliation footer |
| `SPACER` | `---` | Followed by `' '`, `'\t'`, `'\r'`, `'\n'`, `'#'`, or `EOF`; invalid in `QUIPU/1.0` |
| `IDENT` | `[A-Za-z_][A-Za-z0-9_.\-]*` | Bare keys, keywords, anchor names, types |
| `STRING` | `"..."` | JSON-compliant UTF-8 double-quoted string |
| `NUMBER` | `-?(?:0\|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?` | Finite integers (`int`) or IEEE-754 floats (`float`) |
| `PUNCT` | `{ } [ ] ( ) : , \| = @ ~ & * ^ / ?` | Single-character structural tokens |

### 2.3 String Escaping & Literal Rules

- **Strings (`STRING`)**: MUST conform to RFC 8259 JSON string syntax. Supported escape sequences are `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX`. Unescaped `\n` or `\r` inside a string literal is a `QuipuSyntaxError`.
- **Numbers (`NUMBER`)**: Tokens containing `.`, `e`, or `E` parse as `float`; all others parse as base-10 `int`. `NaN`, `Infinity`, `-Infinity`, leading-zero multi-digit integers (`01`), and trailing identifier characters (`12abc`) are rejected.
- **Reserved Bare Literals**: `true` -> `True`, `false` -> `False`, `null` and `_` -> `None`. Bare identifiers other than `true`, `false`, `null`, `_` MUST NOT be used as scalar values (strings MUST be quoted).
- **Bare Map Keys**: An unquoted `IDENT` MAY be used as a map key provided it is not in `{"true", "false", "null", "_"}`. Any other key (including empty strings, spaces, or reserved words) MUST be double-quoted as a `STRING`.

---

## 3. Formal EBNF Grammar

```ebnf
document      ::= [ NEWLINE* header ] NEWLINE* root NEWLINE* [ seal NEWLINE* ] EOF ;

header        ::= "~=" IDENT "/" NUMBER header_attr* ;
header_attr   ::= IDENT "=" ( STRING | IDENT | NUMBER ) ;

seal          ::= "=~" seal_attr+ ;
seal_attr     ::= IDENT "=" ( STRING | IDENT ) ;

root          ::= implicit_map | node ;
implicit_map  ::= map_entry ( ( "," | NEWLINE+ ) map_entry )* [ "," ] ;

map_entry     ::= key decorators ":" NEWLINE* node ;
key           ::= STRING | IDENT ;

node          ::= decorators NEWLINE* value ;
decorators    ::= ( anchor | spin | attachment | tier | polarity | knots | unit | wrap | nether )* ;

anchor        ::= "&" IDENT ;
spin          ::= "~" ( "Z" | "S" ) ;
attachment    ::= "~" ( "R" | "V" ) ;
tier          ::= "@" ( "T0" | "T1" | "T2" | "T3" ) ;
polarity      ::= "@" ( "W" | "D" ) ;
knots         ::= "^knots" "=" STRING ;
unit          ::= "^unit" "=" STRING ;
wrap          ::= "^wrap" "=" STRING ;
nether        ::= "^nether" "=" NUMBER ;

value         ::= braced_map
                | list
                | table
                | alias
                | STRING
                | NUMBER
                | "true" | "false" | "null" | "_" ;

braced_map    ::= "{" NEWLINE* [ map_entry ( ( "," | NEWLINE+ ) map_entry )* [ "," ] ] NEWLINE* "}" ;
list          ::= "[" NEWLINE* [ node ( ( "," | NEWLINE+ ) node )* [ "," ] ] NEWLINE* "]" ;
alias         ::= "*" IDENT ;

table         ::= "@table" "(" col_list ")" top_cords "{" NEWLINE* table_body "}" top_cords ;
col_list      ::= col_def ( "," col_def )* [ "," ] ;
col_def       ::= IDENT ":" IDENT [ "?" ] ;
table_body    ::= ( ( row NEWLINE+ ) | ( "---" NEWLINE* ) )* [ row ] ;
row           ::= cell ( "|" cell )* ;
cell          ::= STRING | NUMBER | "true" | "false" | "null" | "_" ;

top_cords     ::= ( NEWLINE* top_cord )* ;
top_cord      ::= "^count" "=" NUMBER
                | "^sum" "(" IDENT [ "," NUMBER "," NUMBER ] ")" "=" NUMBER
                | "^net" "(" IDENT "," IDENT ")" "=" NUMBER
                | "^equal_sum" "(" IDENT "," IDENT ")" "=" NUMBER
                | "^tol" "(" IDENT [ "," "pct" "=" NUMBER ] ")" "=" NUMBER
                | "^band" "(" IDENT [ "," "ratio" "=" STRING ] ")" "=" NUMBER
                | "^quota" "(" IDENT [ "," "pct" "=" NUMBER ] ")" "=" NUMBER
                | "^layout" "=" STRING ;
```

### 3.1 Map Key & Value Decorator Merging

Decorators on a `map_entry` MAY appear either on the key (`flag ~S @T2: true`) or before the value (`flag: ~S @T2 true`). The parser merges `key_meta` and `val_meta` into one `CordMeta`. Specifying the same decorator category on both sides (e.g. `flag ~S: ~Z true`) MUST raise `QuipuSyntaxError`.

---

## 4. Header Governance, Seals & Canonical Serialization

### 4.1 Header Line (`~=`)

- **`QUIPU/1.0` Header**:
  ```text
  ~= QUIPU/1.0 id="service.release.v1" mode=sealed
  ```
- **`QUIPU/2.0` Header**:
  ```text
  ~= QUIPU/2.0 id="treasury.q4.ledger" mode=sealed tier=working tag="fiscal_reconciliation" parent="quipu-355878d6a9b5" hub="HubA"
  ```

| Header Attribute | Version | Values / Format | AST Field | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `1.0`, `2.0` | Non-empty `STRING` (default `"root"`) | `QuipuDocument.doc_id` | Stable logical document identifier |
| `mode` | `1.0`, `2.0` | `sealed` (default if header present) or `lax` | `QuipuDocument.mode` | Enforces or relaxes mandatory `=~` SHA-256 seal check |
| `tier` | `2.0` | `working`, `summary`, `hybrid` | `QuipuDocument.admin_tier` | Governs row ceiling (`working` MUST have `< 1000` rows per table) |
| `tag` | `2.0` | Safe `STRING` (`^[A-Za-z0-9_.\-/: ]{1,128}$`) | `QuipuDocument.tag` | Domain/topic routing label |
| `parent` | `2.0` | `quipu-[0-9a-f]{12}` | `QuipuDocument.parent` | Cryptographic knot of source packet across upgrades/distillation |
| `hub` | `2.0` | Safe `STRING` (`^[A-Za-z0-9_.\-/: ]{1,128}$`) | `QuipuDocument.hub` | Federated bundle/hub identifier used by `link_quipus()` |

Headerless documents default to `doc_id="root"`, `mode=lax`, and `version="QUIPU/1.0"` (auto-promoted to `"QUIPU/2.0"` if any `2.0` AST primitive is present).

### 4.2 Canonical Body Serialization (`serialize_quipu_body`)

Before computing or verifying a SHA-256 seal, the AST is deterministically serialized into a canonical UTF-8 body string (with `include_header=True`, no trailing newline):

1. **Header Line**:
   `~= <version> id=<json_str(doc_id)> mode=<mode>`
   For `QUIPU/2.0`, append any non-`None` governance attributes in fixed order: `tier=<admin_tier>`, `tag=<json_str(tag)>`, `parent=<json_str(parent)>`, `hub=<json_str(hub)>`.
2. **Blank Separator Line**: Exact single empty line (`""`) after the header.
3. **Root Payload**:
   - If `root.value` is a non-empty `dict` and `root.meta.has_annotations()` is `False`, emit each entry at indent `0` joined by `\n` (implicit top-level map).
   - Otherwise, emit `_format_node(root, indent=0)`.
4. **Canonical Decorator Order**:
   `&<anchor>` -> `~Z`/`~S` (emitted if `explicit_spin` or `spin != Z`) -> `~R`/`~V` -> `@T0..@T3` (emitted if `explicit_tier` or `tier != T0`) -> `@W`/`@D` -> `^unit="..."` -> `^wrap="..."` -> `^nether=<num>` -> `^knots="..."`, joined by single spaces.
5. **Canonical Key & Scalar Formatting**:
   - Keys matching `^[A-Za-z_][A-Za-z0-9_.\-]*$` and not reserved emit bare; all others emit via `json.dumps(key, ensure_ascii=False)`.
   - `None` -> `_`, `True` -> `true`, `False` -> `false`, `int` -> `str(val)`, finite `float` -> `repr(val)`, `str` -> `json.dumps(val, ensure_ascii=False)`.
6. **Canonical Containers & Tables**:
   - Lists of `<= 4` unannotated scalars whose inline form `[a, b]` is `<= 72` chars emit on one line; empty lists emit `[]`; others emit 2-space indented multiline entries.
   - Maps emit `{}` when empty, else 2-space indented `key: value` lines without trailing commas.
   - Tables emit `@table(<col>:<type>, ...)` followed by `^layout="..."` (if set) and `top_cords` in list order, then ` {}` if empty and no spacers, else ` {\n` + 2-space indented `---` spacers and `cell | cell` rows + `\n}`.

### 4.3 SHA-256 Knot Seal Algorithm (`=~`)

Given `body_text = serialize_quipu_body(doc, include_header=True)`:

```python
digest = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
knot = f"quipu-{digest[:12]}"
```

The closing seal line is appended after `\n\n` (one blank line separating body and seal):

```text
=~ knot="quipu-<12hex>" sha256="<64hex>" reconciled=true
```

Because `QLAW_01_MERKLE_SEAL` verifies `compute_quipu_seal(serialize_quipu_body(doc, include_header=True))`, any modification to header metadata, decorators, keys, table cells, spacers, or top-cords invalidates the seal, while harmless comments or whitespace outside canonical strings do not alter the canonical AST hash unless the body semantics change.

---

## 5. Cord Decorators, Registers & Quantization (What & Why)

### 5.1 Complete Cord Decorator Reference

| Decorator | Allowed Version | AST Field & Type | What It Is | Why It Is Needed (Engineering Problem Solved) |
| :--- | :--- | :--- | :--- | :--- |
| `~Z` / `~S` | `1.0`, `2.0` | `CordMeta.spin: CordSpin` (`"Z"` default, `"S"` mutable) | Directional mutability marker distinguishing immutable canonical SSOT cords (`~Z`) from mutable runtime/override cords (`~S`). | Prevents accidental policy/config mutation when merging overrides inside locked containers (`QLAW_05_SPIN_CONTAINMENT`). |
| `~R` / `~V` | `2.0` | `CordMeta.attachment: CordAttachment \| None` (`"R"` / `"V"`) | Branch-side attachment pairing a primary active branch (`~R`) with a shadow, canary, rollback, or verification branch (`~V`). | Co-locates production values and canary/audit twins atomically in one signed document instead of duplicating files or inventing fragile `"key_shadow"` suffixes. |
| `@T0`..`@T3` | `1.0`, `2.0` | `CordMeta.tier: CordTier` (`T0` default .. `T3`) | Four-level provenance trust hierarchy: `T0` verified SSOT, `T1` internal workspace, `T2` external API/webhook, `T3` raw untrusted input. | Enforces taint non-escalation (`QLAW_06_TAINT_NON_ESCALATION`) against prompt injection and supply-chain poisoning (`T0`/`T1` cords cannot alias `T2`/`T3` anchors). |
| `@W` / `@D` | `2.0` | `CordMeta.polarity: CordPolarity \| None` (`"W"` / `"D"`) | Double-entry accounting polarity: credit/asset/budget (`@W`) vs obligation/debt/charge (`@D`). | Makes financial ledgers, token budgets, and resource allocations self-describing for automated audit checks without external schemas. |
| `^unit="..."` | `2.0` | `CordMeta.unit: str \| None` | Explicit physical or semantic unit string (e.g., `"usd"`, `"ms"`, `"bytes"`, `"tokens"`). | Prevents silent unit-mismatch defects (milliseconds vs seconds, cents vs dollars) that bare JSON numbers lose, while `loads()` still returns an unwrapped `int`/`float`. |
| `^wrap="..."` | `2.0` | `CordMeta.wrap: str \| None` | Encoding, cryptographic, or compliance wrapper tag (e.g., `"hmac_sha256"`, `"base64"`, `"semver"`, `"pii_redacted"`). | Transports codec/compliance metadata out-of-band without boxing scalars into verbose `{"encoding": ..., "value": ...}` wrapper dicts. |
| `^nether=<num>` | `2.0` | `CordMeta.nether: int \| float \| None` | Auxiliary finite numeric checksum, sequence epoch, fee weight, or reconciliation delta. | Carries secondary audit weights alongside a primary value without polluting the decoded JSON output of `loads()`. |
| `^knots="..."` | `1.0`, `2.0` | `CordMeta.knots: str \| None` | Positional base-10 integer parity string (`<M>M-<C>C-<D>D-<U>U` or `1E` in `2.0`). | Provides orthogonal human-auditable parity checked by `QLAW_02` to detect silent integer corruption or LLM digit hallucinations. |
| `&id` / `*id` | `1.0`, `2.0` | `CordMeta.anchor` / `CordAlias(target=id)` | Named anchor declaration (`&id`) and acyclic reference (`*id`) resolved during `loads()`. | Eliminates config duplication (DRY) while enforcing bounded DAG expansion (`<= 1024`, `<= 10` chain depth), preventing YAML billion-laughs DoS (`CWE-776`). |

### 5.2 Positional Base-10 Knots & `1E` Figure-Eight Unit

`encode_knots(value: int, *, figure_eight_unit: bool = False) -> str` and `decode_knots(knots: str) -> int` encode/decode signed integers into base-10 positional segments matching `^(-?)(\d+)M-(\d)C-(\d)D-(?:(\d)U|(1)E)$`:

- `M` = thousands ($10^3$), `C` = hundreds ($10^2$), `D` = tens ($10^1$), `U` = units ($10^0$, digits `0..9`).
- **`1E` Figure-Eight Unit Marker (`QUIPU/2.0`)**: When `figure_eight_unit=True` and `abs(value) % 10 == 1`, the units tier encodes as `1E` instead of `1U` (e.g., `encode_knots(41, figure_eight_unit=True) == "0M-0C-4D-1E"`). Both decode identically to `41`, while allowing encoders to distinguish exact singular/sentinel values (`1E`) from multi-state counts (`1U`).

### 5.3 Structural Bit Registers & Logarithmic Scale Quantization

For $O(1)$ routing, log fingerprinting, and index filtering without deserializing the full AST:

- **`encode_7bit(spin=CordSpin.Z, tier=CordTier.T0, *, has_numeric=False, is_table=False) -> str`**:
  Returns a 7-character bit string `[b0, b1, b2, b3, b4, b5, b6]`:
  - `b0 = "1"` (present cord sentinel)
  - `b1 = "1"` if `is_table` else `"0"`
  - `b2 = "1"` if `spin == CordSpin.Z` else `"0"`
  - `b3b4` = tier bits (`"00"`=`T0`, `"01"`=`T1`, `"10"`=`T2`, `"11"`=`T3`)
  - `b5 = "1"` if `has_numeric` else `"0"`
  - `b6 = "1"` (version frame sentinel)
- **`encode_14bit(meta: CordMeta, *, has_numeric=False, is_table=False) -> str`**:
  Appends 7 extended `QUIPU/2.0` bits `[b7..b13]` onto `encode_7bit(...)`:
  - `b7 = "1"` if `meta.attachment is not None` else `"0"`
  - `b8 = "1"` if `meta.attachment == CordAttachment.R` else `"0"`
  - `b9 = "1"` if `meta.polarity is not None` else `"0"`
  - `b10 = "1"` if `meta.polarity == CordPolarity.WHITE` else `"0"`
  - `b11 = "1"` if `(meta.unit is not None or meta.wrap is not None)` else `"0"`
  - `b12 = "1"` if `meta.nether is not None` else `"0"`
  - `b13 = "1"` if `meta.anchor is not None` else `"0"`
- **`SCALE_BUCKETS = (1, 2, 3, 4, 5, 10, 15, 40, 50, 100, 500, 1000)`** & **`quantize_bucket(value: int) -> int`**:
  Maps non-positive ints to `0` and positive ints to the ceiling logarithmic bucket (`<= 1000`, clamping above `1000` to `1000`).
- **`project_quota_population(observed_value: int | float, *, quota_pct: float = 22.5) -> float`**:
  Reconstructs total cohort capacity from a quota observation (`observed_value / (quota_pct / 100.0)`), validating `0.0 < quota_pct <= 100.0` and finite inputs.
- **`render_quipu_micro(doc: QuipuDocument) -> str`**:
  Emits a single-line operational summary containing version, `doc_id`, `mode`, `knot`, `u7` (and `tier`/`u14` in `2.0`), cord count, table count, row count, mutable `S` count, tainted `T2+` count, and total integer `Q^` knots sum.

---

## 6. Typed Tables (`@table`), Spacers (`---`) & Top-Cord Directives

### 6.1 Column Types

Valid column types (`VALID_COLUMN_TYPES`):
`any`, `str`, `int`, `float`, `bool`, and nullable `str?`, `int?`, `float?`, `bool?`.

- `int` strictly rejects `bool` (`True`/`False`).
- `float` strictly rejects `bool`, `int`, and non-finite `NaN`/`Inf`.
- Non-nullable types reject `null`/`_`.
- When `dumps(..., auto_table=True)` converts Python data, any list of `>= 2` dicts sharing identical ordered bare keys (`1..32` columns) and valid table scalar cells compiles automatically into a `QuipuTable` with `^count` and up to 3 `int` `^sum` top-cords.

### 6.2 Row Spacers & Table Directives (What & Why)

| Directive / Feature | Version | Verification Formula (`QLAW_02` / `QLAW_08` / `QLAW_09`) | Engineering Problem Solved |
| :--- | :--- | :--- | :--- |
| `@table(col:type, ...)` | `1.0`, `2.0` | Row arity == column count; every cell matches column type (`QLAW_03`). | Eliminates JSON key repetition across homogeneous records and catches schema/type drift statically. |
| `---` spacer & `^layout` | `2.0` | `spacer_indices` sorted within `[0, len(rows)]`; `^layout` in `{"banded", "seriated"}` (`QLAW_09`). | Partitions rows into structural bands (e.g., Q1–Q2 vs Q3–Q4 or moiety splits) without nested sub-arrays. |
| `^count=N` | `1.0`, `2.0` | `len(table.rows) == N` (`QLAW_02`). | Detects silent row truncation or duplicate-row injection during streaming/LLM output. |
| `^sum(col)=V` | `1.0`, `2.0` | `sum(numeric_cells(col)) == V` (`QLAW_02`). | Verifies total column conservation across the whole table. |
| `^sum(col, start, end)=V` | `2.0` | `0 <= start <= end < len(rows)` and `sum(col[start : end + 1]) == V` (`QLAW_08`). | Audits inclusive sub-ranges/slices (`[start, end]`) against partial truncation or off-by-one extraction. |
| `^net(credit, debt)=N` | `2.0` | `sum(credit) - sum(debt) == N` (`QLAW_08`). | Enforces native double-entry conservation between credit and obligation columns. |
| `^equal_sum(left, right)=P` | `2.0` | `sum(left) == P` and `sum(right) == P` (`QLAW_08`). | Verifies symmetric balance between two independent columns against a shared pivot `P`. |
| `^tol(col, pct=T)=N` | `2.0` | `0 < T <= 100` (default `5.0`); `N <= sum(col) <= N * (1 + T / 100)` (`QLAW_08`). | Guards budgets, token spend, and latency SLOs against overrun or under-delivery (`Tolerance breach`). |
| `^band(col, ratio="R")=V` | `2.0` | Requires `---` spacer; `sum(col) == V > 0` and `sum(col[:spacer[0]]) / V == R`, where `R` in `{"1/2", "1/3", "2/3", "2/5", "3/5"}` (`QLAW_08`). | Verifies proportional allocation across banded partitions separated by `---`. |
| `^quota(col, pct=P)=Pop` | `2.0` | `0 < P <= 100` (default `22.5`); `sum(col) / (P / 100) == Pop` (`QLAW_08`). | Checks sampled/quota subset totals against projected total population capacity. |

---

## 7. Static Verification Laws (`QLAW_01`..`QLAW_10`)

`verify(doc_or_text, *, require_seal=None)` parses the document and runs **7 laws** for `QUIPU/1.0` or **10 laws** for `QUIPU/2.0`:

| Law ID | Scope | Enforced Invariants |
| :--- | :--- | :--- |
| **`QLAW_01_MERKLE_SEAL`** | `1.0`, `2.0` | In `mode=sealed` (or when `=~` is present / `require_seal=True`), `=~` MUST exist, `reconciled` MUST be `true`, and `sha256` + `knot` MUST match `compute_quipu_seal(serialize_quipu_body(doc, include_header=True))`. |
| **`QLAW_02_TOP_CORD_ARITHMETIC`** | `1.0`, `2.0` | All `^count`, full-column `^sum(col)`, and integer `^knots="..."` parity annotations MUST match computed values. |
| **`QLAW_03_COLUMN_TYPES`** | `1.0`, `2.0` | Every `@table` row MUST match header arity and column types (`bool` is never accepted as `int` or `float`). |
| **`QLAW_04_ACYCLIC_ALIASES`** | `1.0`, `2.0` | Every `&anchor` name MUST be unique; every `*alias` MUST resolve to a defined anchor without cycles and within `MAX_ALIAS_EXPANSIONS` (`1_024`). |
| **`QLAW_05_SPIN_CONTAINMENT`** | `1.0`, `2.0` | Nodes with explicit `~S` (mutable) MUST NOT appear inside any ancestor carrying explicit `~Z` (immutable). |
| **`QLAW_06_TAINT_NON_ESCALATION`** | `1.0`, `2.0` | Effective taint inherits monotonically down the tree (`max(parent, child)`). Trusted `@T0`/`@T1` cords MUST NOT alias untrusted `@T2`/`@T3` anchors. |
| **`QLAW_07_SAFETY_BOUNDS`** | `1.0`, `2.0` | Input `<= MAX_QUIPU_BYTES` (`10 MiB`), nesting `<= MAX_QUIPU_DEPTH` (`32`), zero NUL bytes, finite IEEE-754 floats only, unique keys per map. |
| **`QLAW_08_BALANCE_BOUNDS`** | `2.0` | Validates `^sum(col, start, end)`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota`, and finite `^nether`. |
| **`QLAW_09_ACYCLIC_SUM_DAG`** | `2.0` | Validates `@table` `^layout` (`banded`/`seriated`), sorted in-bounds `---` spacer indices, and alias chain depth `<= MAX_COMPOUND_SUM_DEPTH` (`10`). |
| **`QLAW_10_HEADER_TIER_AND_LINEAGE`** | `2.0` | Validates `parent` matches `^quipu-[0-9a-f]{12}$`, `tag`/`hub`/`^unit`/`^wrap` match safe character/length limits (`CWE-20`), and `tier=working` tables have `< MAX_WORKING_ROWS` (`1_000`) rows. |

---

## 8. Version Compatibility & Safety Ceilings

### 8.1 Strict `QUIPU/1.0` vs `QUIPU/2.0` Compatibility

- Documents declaring `~= QUIPU/1.0` MUST NOT contain `2.0`-only header fields (`tier`, `tag`, `parent`, `hub`), `2.0` cord decorators (`~R`, `~V`, `@W`, `@D`, `^unit`, `^wrap`, `^nether`), `---` table spacers, or `2.0` top-cord directives (`^layout`, slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota`). Any occurrence raises `QuipuSyntaxError`.
- Existing `QUIPU/1.0` documents remain 100% valid, verify under `QLAW_01..07`, and preserve byte-identical seals when re-serialized with `dump_quipu(doc, recompute_seal=False)` or `dumps(..., version="1.0")`.
- **Compatibility Shims**:
  - `upgrade_quipu_to_v2(doc_or_text, *, admin_tier=None, tag=None, hub=None, recompute_seal=True)` promotes `1.0 -> 2.0` and records the source seal knot in `parent`.
  - `downgrade_quipu_to_v1(doc_or_text, *, recompute_seal=True)` strips `2.0`-only metadata and directives cleanly without losing JSON payload data.
  - `distill_working_to_summary(doc_or_text, *, doc_id=None)` compacts `tier=working` tables into `tier=summary` envelopes (`row_count`, `column_count`, `band_count`, `numeric_sums`) while linking `parent` to the source knot.
  - `link_quipus(packets, *, hub_id="HubA", doc_id="quipu.linked.bundle")` federates mixed `1.0`/`2.0` packets into a sealed `tier=summary`, `tag="linked_hub"` manifest table.

### 8.2 Security & CWE Safety Ceilings

| Constant / Guard | Default Limit | Mitigated Vulnerability |
| :--- | :--- | :--- |
| `MAX_QUIPU_BYTES` | `10_485_760` (10 MiB) | `CWE-400` Uncontrolled Resource Consumption |
| `MAX_QUIPU_DEPTH` | `32` | Stack exhaustion / deep recursion DoS |
| `MAX_ALIAS_EXPANSIONS` | `1_024` | `CWE-776` Recursive entity / billion-laughs expansion |
| `MAX_COMPOUND_SUM_DEPTH` | `10` | Unbounded DAG alias chain traversal |
| `MAX_WORKING_ROWS` | `1_000` (`< 1000` in `working` tier) | Context/memory saturation on uncompacted working logs |
| Safe Header / Tag Regex | `^[A-Za-z0-9_.\-/: ]{1,128}$` | `CWE-20` Improper Input Validation |
| CLI Path Containment | CWD, `$HOME`, or system temp dir | `CWE-22` Path Traversal |
| NUL & Float Guards | Reject `\x00`, `NaN`, `Inf`, `-Inf` | Parser smuggling & non-JSON float ambiguity |

---

## 9. Andean Epigraphic Heritage Glossary

Every wire keyword and Python API symbol in `QUIPU/2.0` uses concise English. The concepts themselves preserve structural mechanisms identified in Andean *khipu* scholarship:

| Archival Term | Origin | One-Sentence Explanation | `QUIPU/2.0` Equivalent |
| :--- | :--- | :--- | :--- |
| *khipu / quipu* | Quechua | A knotted-cord Andean recording instrument used for quantitative ledgers, administrative censuses, and narrative archives. | `QUIPU/2.0` / `.quipu` |
| *kayte* | Quechua | A categorical marker or rubric cord tied to the primary cord to identify the subject of a cord group. | `tag="..."` |
| *canuto* | Spanish | A tightly wound sleeve of colored thread wrapping a cord segment to carry qualitative provenance or encoding metadata. | `^wrap="..."` |
| *inokatha / nakku* | Aymara / Quechua | A double-entry reconciliation mechanism checking paired credit and obligation cords for zero or target net balance. | `^net(credit, debt)` |
| *yapa / qhincha* | Quechua | The contrast between a permissible small positive margin (*yapa*) and an unacceptable deficit or overrun (*qhincha*). | `^tol(col, pct=N)` |
| *waranqa* | Quechua | A decimal administrative unit of 1,000 households that bounded working-tier ledger granularity before rollup. | `MAX_WORKING_ROWS = 1000` |
| *yupana* | Quechua | A stepped positional counting tray that quantized numbers across discrete logarithmic magnitude tiers. | `SCALE_BUCKETS`, `quantize_bucket()` |
| *khipus enlazados* | Spanish | Physically tied companion khipus federated under a shared supervisory cord for cross-archive reconciliation. | `link_quipus(..., hub_id=...)` |
| *chakana* (knotless spacer) | Quechua | An unknotted spacing interval separating banded cord moieties along the primary cord. | `---` spacer & `^band` |
| *hanan / hurin* (recto / verso) | Quechua | Paired complementary attachment orientations distinguishing upper/primary cords from lower/verification cords. | `~R` / `~V` |
| *Z / S spin* | Epigraphy | Opposite directional fiber ply twists signaling authoritative canonical cords versus subsidiary mutable cords. | `~Z` / `~S` |
| *nudo en ocho* (figure-8 knot) | Spanish | A distinct figure-8 knot used exclusively in the units position to mark the singular value `1`. | `1E` (`figure_eight_unit=True`) |
