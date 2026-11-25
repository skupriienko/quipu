# QUIPU/2.0 & QUIPU/1.0 Format and Verification Specification

- **Document Status**: Normative Protocol Specification
- **Protocol Versions**: `QUIPU/2.0` (Current Default), `QUIPU/1.0` (Legacy Compatible)
- **Media Type**: `application/quipu`
- **File Extension**: `.quipu`
- **Character Encoding**: UTF-8 (NUL `U+0000` strictly forbidden)
- **Default Wire Header**: `~= QUIPU/2.0 id="<doc_id>" mode=sealed`

---

## Table of Contents

1. [Abstract, Normative Language & Conformance Profiles](#1-abstract-normative-language--conformance-profiles)
2. [Byte-Exact Lexical Grammar & Escaping Rules](#2-byte-exact-lexical-grammar--escaping-rules)
3. [Formal EBNF Grammar & Syntax Error Matrix](#3-formal-ebnf-grammar--syntax-error-matrix)
4. [Deterministic Canonical Serialization & SHA-256 Sealing](#4-deterministic-canonical-serialization--sha-256-sealing)
5. [Data Model, JSON AST Contract & Metadata Algebra](#5-data-model-json-ast-contract--metadata-algebra)
6. [Typed Tables, Spacers, Auto-Table Inference & Operational Renderers](#6-typed-tables-spacers-auto-table-inference--operational-renderers)
7. [Formal Specification of Static Verification Laws (`QLAW_01`..`QLAW_10`)](#7-formal-specification-of-static-verification-laws-qlaw_01qlaw_10)
8. [CLI, Stdio JSON-RPC 2.0 MCP Server & Compatibility Policy](#8-cli-stdio-json-rpc-20-mcp-server--compatibility-policy)
9. [Security Considerations & IANA Media Type Registration](#9-security-considerations--iana-media-type-registration)
- [Appendix A: Normative Interoperability Test Vectors](#appendix-a-normative-interoperability-test-vectors)
- [Appendix B: Andean Epigraphic Heritage Glossary](#appendix-b-andean-epigraphic-heritage-glossary)

---

## 1. Abstract, Normative Language & Conformance Profiles

This specification defines the wire syntax, lexical rules, deterministic canonical serialization, SHA-256 cryptographic sealing algorithm, typed Abstract Syntax Tree (AST), JSON projection semantics, static verification laws (`QLAW_01`..`QLAW_10`), operational renderers, CLI contract, and Stdio MCP interface for the **QUIPU** (`.quipu`) structured data and provenance format across versions `QUIPU/1.0` and `QUIPU/2.0`.

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals, as shown here.

### 1.1 Architectural Overview

```text
+--------------------------------------------------------------------------------------+
|                          QUIPU/1.0 & QUIPU/2.0 PROTOCOL PIPELINE                     |
+--------------------------------------------------------------------------------------+
|                                                                                      |
|  UTF-8 .quipu Wire -----> [ Lexer ] -----> [ Parser ] -----> [ QuipuDocument AST ]  |
|   (<= 10 MiB, no NUL)      (Line/Col)       (Depth<=32)            |                 |
|                                                                    |                 |
|       +----------------------------+-------------------------------+------------+    |
|       v                            v                               v            v    |
|  [ JSON Projection ]    [ Canonical Serializer ]      [ Static Verifier ]  [ Views ] |
|  loads() / to_data()    serialize_quipu_body()        QLAW_01..07 (v1.0)   micro()   |
|  Lossless JSON tree     SHA-256 =~ knot footer        QLAW_01..10 (v2.0)   draw()    |
+--------------------------------------------------------------------------------------+
```

### 1.2 Conformance Profiles

Independent implementations in Rust, Go, TypeScript, C++, Python, or other languages MAY claim conformance to one or more of the following four profiles:

| Profile | Name | Mandatory Capabilities |
| :--- | :--- | :--- |
| **Profile A** | **Core Reader / Decoder** | UTF-8 NUL/size pre-checks, lexer and parser (Sections 2–3), strict `QUIPU/1.0` feature gating, bounded acyclic `&anchor`/`*alias` resolution, and lossless JSON data projection (`loads`). |
| **Profile B** | **Canonical Writer & Cryptographic Sealer** | Profile A plus byte-identical `serialize_quipu_body()` (Section 4), SHA-256 `=~` seal generation (`compute_quipu_seal`), `auto_table` compilation (Section 6.3), and lossless AST JSON serialization (`to_dict`/`from_dict`). |
| **Profile C** | **Static Verification Engine** | Profile B plus complete evaluation of `QLAW_01`..`QLAW_07` for `QUIPU/1.0` and `QLAW_01`..`QLAW_10` for `QUIPU/2.0` with exact numeric tolerances and verifier report schema (Section 7). |
| **Profile D** | **Lifecycle, Federation & Tooling** | Profile C plus `upgrade_quipu_to_v2`, `downgrade_quipu_to_v1`, `distill_working_to_summary`, `link_quipus`, `render_quipu_micro`, `render_quipu_ascii`, CLI subcommands, and Stdio JSON-RPC 2.0 MCP server (Section 8). |

---

## 2. Byte-Exact Lexical Grammar & Escaping Rules

### 2.1 Input Stream Constraints

1. Input MUST be valid UTF-8 text.
2. Input MUST NOT contain the NUL code point `U+0000` (`\x00`) anywhere in the stream (including inside strings or comments).
3. Encoded UTF-8 byte length MUST NOT exceed `MAX_QUIPU_BYTES` (`10_485_760` bytes / 10 MiB).
4. Implementations MUST track 1-based `line` and `col` coordinates. Advancing across `U+000A` (`\n`) increments `line` by `1` and resets `col` to `1`; advancing across any other Unicode scalar value increments `col` by `1`.

### 2.2 Whitespace, Line Endings & Comments

- **Horizontal Whitespace**: `U+0020` (space), `U+0009` (tab), and `U+000D` (`\r`) separate tokens and are discarded outside string literals. Consequently, CRLF (`\r\n`) normalizes transparently to a single `NEWLINE` token.
- **Newlines**: `U+000A` (`\n`) emits a `NEWLINE` token. Newlines are structurally significant as terminators for headers, seals, implicit root map entries, braced map entries, list items, and `@table` rows.
- **Line Comments**: Outside string literals, `U+0023` (`#`) starts a comment that consumes all characters up to, but not including, the next `\n` or `EOF`. Comments emit no tokens and do not affect canonical serialization or SHA-256 seals.

### 2.3 Token Definitions & Scanning Priority

The lexer operates in a single left-to-right pass using longest-prefix disambiguation in the exact priority order below:

| Priority | Token Kind | Exact Pattern / Rule | Notes |
| :---: | :--- | :--- | :--- |
| 1 | `HEADER_OP` | `~=` | Two-character operator; MUST precede single `~` |
| 2 | `SEAL_OP` | `=~` | Two-character operator; MUST precede single `=` |
| 3 | `PUNCT` | `{ } [ ] ( ) : , \| = @ ~ & * ^ / ?` | Single-character structural tokens (`LBRACE`, `RBRACE`, `LBRACK`, `RBRACK`, `LPAREN`, `RPAREN`, `COLON`, `COMMA`, `PIPE`, `EQ`, `AT`, `TILDE`, `AMP`, `STAR`, `CARET`, `SLASH`, `QMARK`) |
| 4 | `STRING` | `"..."` | RFC 8259 JSON string literal |
| 5 | `SPACER` | `---` | Emitted ONLY when followed by `EOF` or one of `' '`, `'\t'`, `'\r'`, `'\n'`, `'#'`. Invalid in `QUIPU/1.0`. |
| 6 | `NUMBER` | `-?(?:0\|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?` | Triggered on `-` (when not `SPACER`) or ASCII digit `0..9`. MUST NOT be immediately followed by an ASCII alphanumeric or `_`. |
| 7 | `IDENT` | `[A-Za-z_][A-Za-z0-9_.\-]*` | Bare keys, keywords, decorator tags, anchor names, column names/types. Note `.` and `-` are legal after the first character. |
| 8 | `EOF` | End of input | Appended unconditionally after scanning completes. |

Any character not matching the rules above MUST raise `QuipuSyntaxError` with its 1-based `(line, col)`.

### 2.4 String Escaping, Numbers & Reserved Literals

- **Strings (`STRING`)**:
  - Strings MUST begin and end with `U+0022` (`"`).
  - Unescaped `U+000A` (`\n`), `U+000D` (`\r`), or any unescaped control character in `U+0000..U+001F` inside a string literal MUST raise `QuipuSyntaxError`.
  - Escape sequences MUST conform to RFC 8259 Section 7: `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX` (including valid UTF-16 surrogate pairs `\uD800..\uDBFF` followed by `\uDC00..\uDFFF`).
- **Numbers (`NUMBER`)**:
  - A `NUMBER` token containing `.`, `e`, or `E` MUST decode as an IEEE-754 binary64 floating-point number (`float`). Overflowing literals (e.g., `1e309`) that produce non-finite values MUST raise `QuipuSyntaxError` containing `"Non-finite float"`.
  - A `NUMBER` token without `.`, `e`, or `E` MUST decode as an arbitrary-precision signed base-10 integer (`int`).
  - Negative zero: `-0` decodes as integer `0` (canonicalizes to `0`); `-0.0` decodes as IEEE-754 `-0.0` (canonicalizes to `-0.0`).
  - Leading zeros on multi-digit integers (`01`, `-00`), unary plus (`+5`), bare `NaN`/`Infinity`/`-Infinity`, numeric underscores (`1_000`), and trailing alphanumeric/underscore characters (`12abc`) MUST raise `QuipuSyntaxError`.
- **Reserved Bare Literals**:
  - `_RESERVED_BARE = {"true", "false", "null", "_"}`.
  - In value and `@table` cell positions: `true` -> boolean `true`, `false` -> boolean `false`, `null` and `_` -> `null`.
  - Any other bare `IDENT` in value or `@table` cell position MUST raise `QuipuSyntaxError` (strings MUST be double-quoted).
- **Map Keys**:
  - A bare `IDENT` MAY be used as a map key if and only if it is NOT in `_RESERVED_BARE`.
  - Empty strings, keys starting with digits/hyphens/dots, keys containing spaces/punctuation, and reserved words (`"true"`, `"false"`, `"null"`, `"_"`) MUST be double-quoted as `STRING`.

---

## 3. Formal EBNF Grammar & Syntax Error Matrix

### 3.1 Normative EBNF Grammar

```ebnf
document      ::= NEWLINE* [ header ] NEWLINE* root NEWLINE* [ seal NEWLINE* ] EOF ;

header        ::= "~=" IDENT "/" NUMBER header_attr* ;
header_attr   ::= IDENT "=" ( STRING | IDENT | NUMBER ) ;

seal          ::= "=~" seal_attr+ ;
seal_attr     ::= IDENT "=" ( STRING | IDENT ) ;

root          ::= implicit_map | node ;
implicit_map  ::= map_entry ( ( "," | NEWLINE+ ) map_entry )* [ "," ] ;

map_entry     ::= key decorators ":" NEWLINE* node ;
key           ::= STRING | bare_ident ;        (* bare_ident := IDENT - _RESERVED_BARE *)

node          ::= decorators NEWLINE* value ;
decorators    ::= ( anchor | spin | attachment | tier | polarity
                  | knots | unit | wrap | nether )* ;

anchor        ::= "&" IDENT ;
spin          ::= "~" ( "Z" | "S" ) ;
attachment    ::= "~" ( "R" | "V" ) ;          (* QUIPU/2.0 only *)
tier          ::= "@" ( "T0" | "T1" | "T2" | "T3" ) ;
polarity      ::= "@" ( "W" | "D" ) ;          (* QUIPU/2.0 only *)
knots         ::= "^knots" "=" STRING ;
unit          ::= "^unit" "=" STRING ;         (* QUIPU/2.0 only *)
wrap          ::= "^wrap" "=" STRING ;         (* QUIPU/2.0 only *)
nether        ::= "^nether" "=" NUMBER ;       (* QUIPU/2.0 only *)

value         ::= braced_map
                | list
                | table
                | alias
                | STRING
                | NUMBER
                | "true" | "false" | "null" | "_" ;

braced_map    ::= "{" NEWLINE*
                  [ map_entry ( ( "," | NEWLINE+ ) map_entry )* [ "," ] ]
                  NEWLINE* "}" ;

list          ::= "[" NEWLINE*
                  [ node ( ( "," | NEWLINE+ ) node )* [ "," ] ]
                  NEWLINE* "]" ;

alias         ::= "*" IDENT ;

table         ::= "@table" "(" col_list ")" top_cords
                  NEWLINE* "{" NEWLINE* table_body "}" top_cords ;
col_list      ::= col_def ( "," NEWLINE* col_def )* [ "," ] NEWLINE* ;
col_def       ::= IDENT ":" IDENT [ "?" ] ;
table_body    ::= ( ( row ( NEWLINE+ | &("}") ) ) | ( "---" NEWLINE* ) )* ;
row           ::= cell ( "|" cell )* ;         (* exact arity == len(col_list) *)
cell          ::= STRING | NUMBER | "true" | "false" | "null" | "_" ;

top_cords     ::= ( NEWLINE* top_cord )* ;
top_cord      ::= "^count" "=" INT
                | "^sum" "(" IDENT ")" "=" NUMBER
                | "^sum" "(" IDENT "," INT "," INT ")" "=" NUMBER            (* QUIPU/2.0 *)
                | "^net" "(" IDENT "," IDENT ")" "=" NUMBER                  (* QUIPU/2.0 *)
                | "^equal_sum" "(" IDENT "," IDENT ")" "=" NUMBER            (* QUIPU/2.0 *)
                | "^tol" "(" IDENT [ "," "pct" "=" NUMBER ] ")" "=" NUMBER   (* QUIPU/2.0 *)
                | "^band" "(" IDENT [ "," "ratio" "=" STRING ] ")" "=" NUMBER (* QUIPU/2.0 *)
                | "^quota" "(" IDENT [ "," "pct" "=" NUMBER ] ")" "=" NUMBER (* QUIPU/2.0 *)
                | "^layout" "=" STRING ;                                     (* QUIPU/2.0 *)
```

### 3.2 Parser Disambiguation & Semantic Rules

1. **Implicit Root Map Lookahead**: After the optional header, the parser performs bounded lookahead: if the first token is a valid map `key`, followed by zero or more valid `decorators`, followed immediately (without crossing a newline) by `":"`, the root MUST parse as `implicit_map`; otherwise it MUST parse as a single `node` (allowing scalar, list, `@table`, braced map, or annotated root documents).
2. **Map Key vs. Value Decorator Merging**: On `map_entry`, decorators MAY appear on the key side (`k ~S @T2: 1`), the value side (`k: ~S @T2 1`), or split across both (`k ~S: @T2 1`). The parser merges both `CordMeta` records. Declaring the same decorator category (`spin`, `tier`, `anchor`, `knots`, `attachment`, `polarity`, `unit`, `wrap`, `nether`) twice on one side OR on both sides MUST raise `QuipuSyntaxError`.
3. **Duplicate Keys & Columns**: Duplicate keys within any map (implicit root or braced) and duplicate column names within `@table(...)` MUST raise `QuipuSyntaxError`.
4. **Pre-Brace and Post-Brace Top-Cords**: `@table` parsers MUST accept `top_cords` both before `{` and after `}`, appending them in encounter order. If `^layout` is specified more than once, the final declaration wins.
5. **Nesting Depth Enforcement**: Root node starts at `depth = 0`. Entering each child of a map or list increments `depth` by `1`; entering `@table` checks `depth + 1 > MAX_QUIPU_DEPTH`. Exceeding `MAX_QUIPU_DEPTH` (`32`) MUST raise `QuipuSyntaxError`.
6. **Strict `QUIPU/1.0` Gating**: When a document explicitly declares `~= QUIPU/1.0`, any `QUIPU/2.0` header attribute (`tier`, `tag`, `parent`, `hub`), decorator (`~R`, `~V`, `@W`, `@D`, `^unit`, `^wrap`, `^nether`), table spacer (`---`), or table directive (`^layout`, slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota`) MUST raise `QuipuSyntaxError`.
7. **Headerless Promotion**: When no `~=` header is present, `doc_id` defaults to `"root"`, `mode` defaults to `lax`, and `version` defaults to `"QUIPU/1.0"`. After parsing `root`, if any AST node contains a `QUIPU/2.0` decorator (`attachment`, `polarity`, `unit`, `wrap`, `nether`) or any `@table` contains `spacer_indices`, `layout`, or a `QUIPU/2.0` top-cord, `version` MUST auto-promote to `"QUIPU/2.0"`. Note that `1E` inside `^knots="..."` alone does NOT trigger auto-promotion.

### 3.3 Normative Syntax Error vs. Static Verification Matrix

Implementers MUST distinguish parse-time rejections (`QuipuSyntaxError`) from structurally valid ASTs that fail static verification (`QLAW_*`):

| Input Condition / Example | Expected Stage & Result |
| :--- | :--- |
| Empty input or header-only input (no root payload) | `QuipuSyntaxError` (`QLAW_00_SYNTAX` in verifier) |
| NUL byte `\x00` anywhere in text | `QuipuSyntaxError` -> `QLAW_07_SAFETY_BOUNDS` (`SAFETY_VIOLATION`) |
| Payload byte length `> 10_485_760` | `QuipuSyntaxError` -> `QLAW_07_SAFETY_BOUNDS` (`SAFETY_VIOLATION`) |
| Nesting depth `> 32` | `QuipuSyntaxError` -> `QLAW_07_SAFETY_BOUNDS` (`SAFETY_VIOLATION`) |
| Non-finite float overflow (`1e309`) | `QuipuSyntaxError` -> `QLAW_07_SAFETY_BOUNDS` (`SAFETY_VIOLATION`) |
| Unquoted string value (`name: hello`) or `NaN` / `Infinity` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Leading-zero integer (`01`), trailing alpha (`12x`), unescaped `\n` in string | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Duplicate key in map (`{a: 1, a: 2}`) or duplicate `@table` column | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Duplicate or conflicting decorator (`k ~Z: ~S 1`, `k @T0 @T1: 1`) | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Unsupported version (`~= QUIPU/3.0`), empty `id=""`, invalid `mode=strict` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| `=~` missing `knot` or `sha256`, or `reconciled` not in `{"true", "false"}` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Any `QUIPU/2.0` feature inside explicit `~= QUIPU/1.0` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Wire `@table` row with wrong pipe count (e.g. 2 cells in 3-col table) | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) |
| Missing `=~` seal in `mode=sealed` or mismatched `sha256` / `knot` | Parses into AST -> fails `QLAW_01_MERKLE_SEAL` |
| Wrong `^count`, wrong full `^sum`, or mismatched/malformed `^knots="..."` | Parses into AST -> fails `QLAW_02_TOP_CORD_ARITHMETIC` |
| `@table` cell type mismatch (e.g. `true` in `int` col, `_` in non-nullable col) | Parses into AST -> fails `QLAW_03_COLUMN_TYPES` |
| Duplicate `&anchor`, undefined `*alias`, cyclic `*alias`, `> 1024` expansions | Parses into AST -> fails `QLAW_04_ACYCLIC_ALIASES` |
| Explicit `~S` node nested inside explicit `~Z` ancestor | Parses into AST -> fails `QLAW_05_SPIN_CONTAINMENT` |
| `@T0`/`@T1` cord aliasing a `@T2`/`@T3` anchor | Parses into AST -> fails `QLAW_06_TAINT_NON_ESCALATION` |
| Slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota` failure | Parses into AST -> fails `QLAW_08_BALANCE_BOUNDS` |
| Invalid `^layout` string, unsorted spacers, or alias chain depth `> 10` | Parses into AST -> fails `QLAW_09_ACYCLIC_SUM_DAG` |
| Invalid `parent`, unsafe `tag`/`hub`/`^unit`/`^wrap`, or `working` rows `>= 1000` | Parses into AST -> fails `QLAW_10_HEADER_TIER_AND_LINEAGE` |

---

## 4. Deterministic Canonical Serialization & SHA-256 Sealing

To guarantee 100% cross-language byte compatibility and identical SHA-256 seals across Rust, Go, TypeScript, C++, and Python, Profile B implementations MUST follow the exact algorithm below.

### 4.1 Header Line Specification (`~=`)

| Attribute | Version | Syntax / Constraints | AST Field | Default if Omitted |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `1.0`, `2.0` | Non-empty `STRING` | `doc_id` | `"root"` |
| `mode` | `1.0`, `2.0` | `sealed` or `lax` | `mode` | `sealed` (with header); `lax` (headerless) |
| `tier` | `2.0` | `working`, `summary`, or `hybrid` | `admin_tier` | `None` |
| `tag` | `2.0` | `STRING` matching `^[A-Za-z0-9_.\-/: ]{1,128}$` | `tag` | `None` |
| `parent` | `2.0` | `STRING` matching `^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}\|none)$` | `parent` | `None` |
| `hub` | `2.0` | `STRING` matching `^[A-Za-z0-9_.\-/: ]{1,128}$` | `hub` | `None` |

Producers MUST ONLY emit the attributes in the table above. Parsers MUST reject `tier`, `tag`, `parent`, and `hub` when the header declares `QUIPU/1.0`. Unrecognized header attributes MAY be ignored by permissive parsers and MUST NOT be emitted by canonical serializers.

### 4.2 Step-by-Step Algorithm for `serialize_quipu_body(doc, include_header=True)`

Line endings in canonical output MUST be LF (`\n`, `0x0A`) only. `serialize_quipu_body()` returns a string with **no trailing newline**.

1. **Header Emission** (when `include_header` is `true`):
   - Emit `~= <version> id=<canon_str(doc_id)> mode=<mode>`.
   - If `version == "QUIPU/2.0"`, append each non-`None` governance field separated by a single space in exact fixed order:
     1. `tier=<admin_tier>` (unquoted identifier)
     2. `tag=<canon_str(tag)>`
     3. `parent=<canon_str(parent)>`
     4. `hub=<canon_str(hub)>`
   - Follow the header line with one blank line (`""`).
2. **Root Payload Framing**:
   - If `root.value` is a non-empty map (`dict`) AND `root.meta.has_annotations()` is `false`: emit each `(key, child_node)` at `indent = 0` in insertion order, separated by `\n` (implicit top-level map).
   - Otherwise: emit `format_node(root, indent=0)`.
3. **Canonical Decorator Order (`format_decorators(meta)`)**:
   Join present decorators with a single ASCII space in exact fixed order:
   1. `&<anchor>` (if `anchor is not None`)
   2. `~<spin>` (if `explicit_spin` is `true` OR `spin != "Z"`)
   3. `~<attachment>` (if `attachment is not None`)
   4. `@<tier>` (if `explicit_tier` is `true` OR `tier != "T0"`)
   5. `@<polarity>` (if `polarity is not None`)
   6. `^unit=<canon_str(unit)>` (if `unit is not None`)
   7. `^wrap=<canon_str(wrap)>` (if `wrap is not None`)
   8. `^nether=<canon_num(nether)>` (if `nether is not None`)
   9. `^knots=<canon_str(knots)>` (if `knots is not None`)
4. **Canonical String Escaping (`canon_str(s)`)**:
   - Wrap in `"..."`.
   - Escape `"` as `\"`, `\` as `\\`, `U+0008` as `\b`, `U+000C` as `\f`, `U+000A` as `\n`, `U+000D` as `\r`, `U+0009` as `\t`, and all remaining control characters `U+0000..U+001F` as lowercase `\u00xx`.
   - Do NOT escape `/` (`U+002F`).
   - Emit all printable ASCII (`U+0020..U+007F` except `"` and `\`) and all Unicode code points `>= U+0080` as literal unescaped UTF-8 bytes (matching Python `json.dumps(s, ensure_ascii=False)`).
5. **Canonical Key & Scalar Formatting**:
   - **Map Key**: If `key` matches `^[A-Za-z_][A-Za-z0-9_.\-]*$` AND `key not in {"true", "false", "null", "_"}`, emit `key` bare; otherwise emit `canon_str(key)`.
   - **Map Entry**: `(" " * indent) + (f"{k} {dec}" if dec else k) + ": " + format_value(node.value, indent)`.
   - **Null**: `_` (never `null`).
   - **Boolean**: `true` or `false`.
   - **Integer**: Base-10 decimal string with no leading zeros and optional `-` (e.g., `0`, `-42`, `1000`).
   - **IEEE-754 Float**: Reject `NaN`, `+Infinity`, `-Infinity`. Emit shortest round-trip decimal representation that parses back to the identical IEEE-754 binary64 bit pattern (matching Python `repr(float)` / ECMAScript / Rust `ryu`-compatible formatting: always includes a decimal point or exponent, e.g., `0.0`, `-0.0`, `1.5`, `1e-05` for `|x| < 1e-4` and `1e+16` for `|x| >= 1e16`).
   - **String**: `canon_str(val)`.
6. **Canonical Lists (`format_list(items, indent)`)**:
   - Empty list: `[]`.
   - Inline heuristic: If `len(items) <= 4` AND every item has `not item.meta.has_annotations()` AND `item.value` is a scalar (`null`, `bool`, `int`, `float`, `str`), construct `inline = "[" + ", ".join(format_scalar(x.value)) + "]"`. If `len(inline) <= 72` (measured in Unicode code points), emit `inline`.
   - Otherwise emit multiline with `2 * depth` leading spaces (`pad = " " * indent`):
     ```text
     [
       <format_node(item_0, indent + 2)>,
       ...
       <format_node(item_last, indent + 2)>
     ]
     ```
     No trailing comma on the final element.
7. **Canonical Braced Maps (`format_map(entries, indent)`)**:
   - Empty map: `{}`.
   - Non-empty map: `"{\n"` + each entry via `format_map_entry(k, v, indent + 2)` joined by `"\n"` + `"\n" + (" " * indent) + "}"`. No trailing commas.
8. **Canonical Tables (`format_table(table, indent)`)**:
   - Header: `@table(` + `", ".join(f"{name}:{ctype}")` + `)`.
   - Directives: If `table.layout is not None`, prepend `^layout=<canon_str(layout)>`, followed by each `tc` in `table.top_cords` in list order, joined by single spaces (with a single leading space after `)` if non-empty):
     - `count`: `^count=<expected>`
     - `sum` (full): `^sum(<col>)=<expected>`
     - `sum` (slice): `^sum(<col>, <start>, <end>)=<expected>`
     - `net` / `equal_sum`: `^<kind>(<col>, <end_col>)=<expected>`
     - `tol` / `quota`: `^<kind>(<col>, pct=<tolerance_pct>)=<expected>` (omit `, pct=...` only if `tolerance_pct is None`)
     - `band`: `^band(<col>, ratio=<canon_str(ratio)>)=<expected>` (omit `, ratio=...` only if `ratio` is falsy)
   - Empty table with no spacers: `<header><directives> {}`.
   - Non-empty (or containing spacers): `<header><directives> {\n`, then for each `r_idx` in `0..len(rows)-1`, emit `(" " * (indent + 2)) + "---"` once per occurrence of `r_idx` in `spacer_indices`, followed by `(" " * (indent + 2)) + " | ".join(format_scalar(cell))`. After all rows, emit any spacers at index `len(rows)`. Close with `\n` + `(" " * indent) + "}"`.

### 4.3 SHA-256 Cryptographic Seal (`=~`)

Given `body = serialize_quipu_body(doc, include_header=True)` (UTF-8 encoded, no trailing `\n`):

```text
digest = lowercase_hex(SHA256(UTF8_BYTES(body)))    # 64 hex characters
knot   = "quipu-" + digest[:12]                     # 18 ASCII characters
```

When emitting a sealed wire document (`dump_quipu` with `include_header=True`):

```text
<body_without_trailing_lf>\n\n=~ knot="<knot>" sha256="<digest>" reconciled=true\n
```

When emitting an unsealed wire document (`seal is None` or `include_header=False`):

```text
<body_without_trailing_lf>\n
```

**Reference Seal Verification**: For `examples/ledger_sealed.quipu`, hashing its canonical body yields:

- `knot`: `"quipu-a351f60d7a7d"`
- `sha256`: `"a351f60d7a7d135169a6f00b4220dcaf5b8d7b87e8693ae3820f37ea65997854"`

---

## 5. Data Model, JSON AST Contract & Metadata Algebra

### 5.1 Cord Decorators (What & Why)

All decorators attach to `QuipuNode.meta` (`CordMeta`) and strip cleanly during `loads()` so standard JSON consumers receive plain unwrapped values:

| Decorator | Version | AST Field & Type | What It Is | Engineering Problem Solved |
| :--- | :--- | :--- | :--- | :--- |
| `~Z` / `~S` | `1.0`, `2.0` | `spin: CordSpin` (`"Z"` default, `"S"` mutable) | Directional mutability marker distinguishing immutable SSOT cords (`~Z`) from mutable override cords (`~S`). | Prevents accidental policy mutation inside locked configuration subtrees (`QLAW_05`). |
| `~R` / `~V` | `2.0` | `attachment: CordAttachment \| None` (`"R"`/`"V"`) | Branch-side attachment pairing a primary branch (`~R`) with a shadow/canary/verification twin (`~V`). | Co-locates live and canary/audit parameters atomically inside one signed file without fragile `"_shadow"` key suffixes. |
| `@T0`..`@T3` | `1.0`, `2.0` | `tier: CordTier` (`T0` default .. `T3`) | Four-level provenance trust hierarchy: `T0` verified SSOT, `T1` internal workspace, `T2` external API/webhook, `T3` raw untrusted input. | Enforces taint non-escalation (`QLAW_06`) so trusted cords cannot alias untrusted payloads. |
| `@W` / `@D` | `2.0` | `polarity: CordPolarity \| None` (`"W"`/`"D"`) | Double-entry accounting polarity: credit/asset/budget (`@W`) vs obligation/debt/charge (`@D`). | Makes ledgers, token budgets, and allocations self-describing for automated audit checks. |
| `^unit="..."` | `2.0` | `unit: str \| None` | Physical or semantic unit label (`"usd"`, `"ms"`, `"bytes"`, `"tokens"`). | Prevents silent unit-mismatch defects without boxing numbers in wrapper objects. |
| `^wrap="..."` | `2.0` | `wrap: str \| None` | Codec, cryptographic, or compliance wrapper tag (`"hmac_sha256"`, `"base64"`, `"pii_redacted"`). | Transports encoding provenance out-of-band without altering decoded scalar values. |
| `^nether=<num>` | `2.0` | `nether: int \| float \| None` | Auxiliary finite numeric epoch, fee weight, or reconciliation delta. | Carries secondary audit weights alongside a primary value without polluting `loads()`. |
| `^knots="..."` | `1.0`, `2.0` | `knots: str \| None` | Positional base-10 integer parity string (`<M>M-<C>C-<D>D-<U>U` or `1E`). | Detects silent integer corruption or LLM digit hallucinations (`QLAW_02`). |
| `&id` / `*id` | `1.0`, `2.0` | `anchor: str \| None` / `CordAlias(target=id)` | Named anchor declaration (`&id`) and bounded acyclic reference (`*id`). | Eliminates config duplication while preventing exponential alias bombs (`CWE-776`). |

### 5.2 Base-10 Knot Encoding (`encode_knots` / `decode_knots`)

Signed non-boolean integers map deterministically to positional base-10 strings matching:

```text
^(-?)(\d+)M-(\d)C-(\d)D-(?:(\d)U|(1)E)$
```

- `M` = $\lfloor |v| / 1000 \rfloor$, `C` = $\lfloor (|v| \bmod 1000) / 100 \rfloor$, `D` = $\lfloor (|v| \bmod 100) / 10 \rfloor$, `U` = $|v| \bmod 10$.
- **`1E` Singular Unit Marker**: When `figure_eight_unit=True` and $|v| \bmod 10 = 1$, the units segment encodes as `1E` instead of `1U` (e.g., `41 -> "0M-0C-4D-1E"`). `decode_knots()` decodes both `1U` and `1E` to unit digit `1`.

### 5.3 Structural Bit Registers, Scale Buckets & Quota Projection

- **7-Bit Structural Register (`encode_7bit`)**: Returns `[b0, b1, b2, b3, b4, b5, b6]`:
  - `b0`: `"1"` (present sentinel)
  - `b1`: `"1"` if `is_table` else `"0"`
  - `b2`: `"1"` if `spin == "Z"` else `"0"`
  - `b3b4`: `"00"` (`T0`), `"01"` (`T1`), `"10"` (`T2`), `"11"` (`T3`)
  - `b5`: `"1"` if `has_numeric` else `"0"`
  - `b6`: `"1"` (frame sentinel)
- **14-Bit Extended Register (`encode_14bit`)**: Appends `[b7..b13]` onto `encode_7bit`:
  - `b7`: `attachment is not None`
  - `b8`: `attachment == "R"`
  - `b9`: `polarity is not None`
  - `b10`: `polarity == "W"`
  - `b11`: `unit is not None or wrap is not None`
  - `b12`: `nether is not None`
  - `b13`: `anchor is not None`
- **Logarithmic Scale Buckets**: `SCALE_BUCKETS = (1, 2, 3, 4, 5, 10, 15, 40, 50, 100, 500, 1000)`. `quantize_bucket(v: int)` rejects `bool`, returns `0` for `v <= 0`, returns the smallest bucket `b >= v`, and clamps `v > 1000` to `1000`.
- **Inverse Quota Projection**: `project_quota_population(observed, quota_pct=22.5)` rejects `bool` and non-finite inputs, requires `0.0 < quota_pct <= 100.0`, and returns `float(observed) / (float(quota_pct) / 100.0)`.

### 5.4 Normative JSON AST Representation (`to_dict()` / `from_dict()`)

Unlike `loads()` (which strips all metadata, resolves `*alias`, and converts `@table` to `list[dict]`), `QuipuDocument.to_dict()` emits a lossless JSON AST contract:

| AST Type | JSON Object Schema | Notes |
| :--- | :--- | :--- |
| `QuipuDocument` | `{"version": str, "doc_id": str, "mode": "sealed"\|"lax", "root": QuipuNode, "seal": QuipuSeal\|null, ...}` | Optional `2.0` keys (`"admin_tier"`, `"tag"`, `"parent"`, `"hub"`) are omitted when `None`. `from_dict()` defaults omitted `"version"` to `"QUIPU/1.0"`. |
| `QuipuSeal` | `{"knot": str, "sha256": str, "reconciled": bool}` | `reconciled` defaults to `true` in `from_dict()`. |
| `QuipuNode` | `{"value": <scalar \| list[QuipuNode] \| dict[str, QuipuNode] \| TableBox \| AliasBox>, "meta": CordMeta}` | Tagged wrappers: `TableBox = {"__quipu_table__": QuipuTable}`, `AliasBox = {"__quipu_alias__": str}`. |
| `CordMeta` | `{"spin": "Z"\|"S", "tier": "T0".."T3", "anchor": str\|null, "knots": str\|null, "explicit_spin": bool, "explicit_tier": bool, ...}` | Optional `2.0` keys (`"attachment"`, `"polarity"`, `"unit"`, `"wrap"`, `"nether"`) are omitted when `None`. |
| `QuipuTable` | `{"columns": [{"name": str, "type": str}], "rows": [[scalar, ...]], "top_cords": [TopCordSpec], ...}` | Optional keys `"spacer_indices"` (omitted if empty) and `"layout"` (omitted if `None`). |
| `TopCordSpec` | `{"kind": str, "column": str\|null, "expected": int\|float, ...}` | Optional keys (`"end_column"`, `"start_row"`, `"end_row"`, `"tolerance_pct"`, `"ratio"`) omitted when `None`. |

---

## 6. Typed Tables, Spacers, Auto-Table Inference & Operational Renderers

### 6.1 Column Types

`VALID_COLUMN_TYPES = {"any", "str", "int", "float", "bool", "str?", "int?", "float?", "bool?"}`.

- `int` matches signed integers and MUST reject `bool`.
- `float` matches finite IEEE-754 floats and MUST reject `bool`, `int`, and non-finite floats.
- `bool` matches `true`/`false` only; `str` matches UTF-8 strings only.
- `?` suffix permits `null` (`_`); non-nullable types MUST reject `null`. `any` permits any table scalar.

### 6.2 Table Directives Summary

| Directive | Version | Enforced Formula | Law |
| :--- | :--- | :--- | :--- |
| `^count=N` | `1.0`, `2.0` | `len(rows) == N` | `QLAW_02` |
| `^sum(col)=V` | `1.0`, `2.0` | `sum(numeric_cells(col)) == V` | `QLAW_02` |
| `^sum(col, s, e)=V` | `2.0` | `0 <= s <= e < len(rows)` and `sum(col[s..e]) == V` (inclusive) | `QLAW_08` |
| `^net(c1, c2)=N` | `2.0` | `sum(c1) - sum(c2) == N` | `QLAW_08` |
| `^equal_sum(c1, c2)=P` | `2.0` | `sum(c1) == P` and `sum(c2) == P` | `QLAW_08` |
| `^tol(col, pct=T)=N` | `2.0` | `0 < T <= 100` (default `5.0`); `N <= sum(col) <= N * (1 + T / 100)` | `QLAW_08` |
| `^band(col, ratio="R")=V` | `2.0` | Requires `---` spacer; `sum(col) == V > 0` and `sum(col[:spacer[0]]) / V == R` | `QLAW_08` |
| `^quota(col, pct=P)=Pop` | `2.0` | `0 < P <= 100` (default `22.5`); `sum(col) / (P / 100) == Pop` | `QLAW_08` |
| `^layout="L"` & `---` | `2.0` | `L in {"banded", "seriated"}`; spacers sorted in `[0, len(rows)]` | `QLAW_09` |

### 6.3 Automatic Table Inference (`auto_table=True`)

When `data_to_quipu(..., auto_table=True)` encodes a JSON array `items`, it compiles `items` into a `QuipuTable` if and only if ALL of the following hold:

1. `len(items) >= 2` and every element is a map (`dict`).
2. `first_keys = tuple(items[0].keys())` has length `1 <= len(first_keys) <= 32`.
3. Every key in `first_keys` is a `str` matching `^[A-Za-z_][A-Za-z0-9_.\-]*$` and NOT in `_RESERVED_BARE`.
4. Every subsequent record has the exact same ordered key tuple `tuple(rec.keys()) == first_keys`.
5. Every cell value is a valid table scalar (`None`, `bool`, `int`, `str`, or finite `float`).

For each column, type inference inspects all non-`None` values by exact runtime type:

- If all values are `None`, OR more than one distinct type appears (including mixed `int` and `float`), the inferred column type is `"any"`. (It does NOT coerce `int` to `float` and does NOT fall back to a list.)
- Otherwise the inferred type is `bool`, `int`, `float`, or `str`, suffixed with `?` if any row contains `None`.

Automatically compiled tables generate `^count=<len(rows)>` plus `^sum(<col>)=<sum>` for up to the first `3` columns whose inferred type is strictly `"int"` (non-nullable).

### 6.4 Operational & Visual Renderers

#### Single-Line Micro Fingerprint (`render_quipu_micro(doc)`)

Emits one deterministic summary line:

```text
QUIPU/1.0:
[QUIPU/1.0 id=<id> mode=<mode> knot=<knot|unsealed> u7=<7bits>] cords=<C> tables=<T> rows=<R> S=<S> T2+=<U> Q^=<knots>

QUIPU/2.0:
[QUIPU/2.0 id=<id> mode=<mode> knot=<knot|unsealed> u7=<7bits>( tier=<tier>)? u14=<14bits>] cords=<C> tables=<T> rows=<R> S=<S> T2+=<U> Q^=<knots>
```

`Q^` is `encode_knots(numeric_sum)` over all non-boolean integer scalar nodes and `@table` cells (aliases are not expanded).

#### Visual Cord Diagram (`render_quipu_ascii(doc_or_text, *, max_rows=8, max_chars=MAX_ASCII_CHARS)`)

Aliases: `draw_quipu`, `draw`. Safety ceiling: `MAX_ASCII_CHARS = 8_000`.

- Renders an 88-column diagram with header `=== <version>: <doc_id> [mode=<mode> ... | knot=<knot>] ===`, upward Top-Cord block (`▲ [<path>] ...`), horizontal Primary Cord (`(LOOP)` + 74×`═` + `(TASSEL)`), top-level Pendants (`│── Pendant`), nested Subsidiaries (`├── ↳ Subsidiary` / `└── ↳ Subsidiary`, capped at visual depth `6` with `... (max depth reached)`), Alias pointers (`⤴ *<target> (alias)`), table band spacers (`├── ┄┄┄ [--- band spacer] ┄┄┄`), and decimal knot glyphs (`●` / `●×N` for M/C/D, `●(1U)` / `≈NT≈` for U, `⟨1E⟩` for figure-eight singular unit, `[0 gap]` for zero).
- Lists, maps, and tables truncate after `max_rows` entries with `... (+<remaining> more items|rows)`.
- If total output exceeds `max_chars`, output is truncated to `out[:max(64, max_chars - 32)] + "\n... [TRUNCATED_TO_MAX_ASCII_CHARS]"`.

---

## 7. Formal Specification of Static Verification Laws (`QLAW_01`..`QLAW_10`)

`verify_quipu(doc_or_text, *, require_seal=None)` executes `QLAW_01`..`QLAW_07` for `QUIPU/1.0` and `QLAW_01`..`QLAW_10` for `QUIPU/2.0`.

### 7.1 Exact Numeric Comparison Tolerances

| Comparison Context | Exact Mathematical Rule |
| :--- | :--- |
| Integer-to-integer (`^count`, `^sum`, `^net`, `^equal_sum`) | Exact arbitrary-precision integer equality: `a == b` (when both operands are `int`). |
| Float comparison (`_num_equal`) | `math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-9)` (when either operand is `float`). |
| Tolerance range (`^tol(col, pct=T)=N`) | Valid iff `0 < T <= 100` AND `actual + 1e-9 >= N` AND `actual <= N * (1 + T / 100) + 1e-9`. |
| Band ratio (`^band(col, ratio="R")=V`) | Valid `R` in `{"1/2": 0.5, "1/3": 1/3, "2/3": 2/3, "2/5": 0.4, "3/5": 0.6}`. Valid iff `_num_equal(total, V)` AND `total > 0` AND `math.isclose(first_band / total, target_ratio, rel_tol=1e-6, abs_tol=1e-6)`, where `first_band = sum(col[0 : spacer_indices[0]])`. |
| Quota projection (`^quota(col, pct=P)=Pop`) | Valid iff `0 < P <= 100` AND `math.isclose(total / (P / 100), float(Pop), rel_tol=1e-6, abs_tol=1.0)`. |

### 7.2 Metadata Inheritance & Graph Algebra

- **Monotonic Taint Inheritance**: Root starts with `inherited_tier = T0`. At every node:

$$\text{eff\_tier}(\text{node}) = \arg\max_{t \in \{\text{inherited\_tier},\, \text{node.meta.tier}\}} \text{rank}(t), \quad \text{rank}(T0)=0, T1=1, T2=2, T3=3.$$

Anchors record their `eff_tier` during the document walk.
- **Spin Containment Propagation**: Root starts with `in_explicit_z = false`. A child inherits `next_in_z = in_explicit_z OR (node.meta.explicit_spin AND node.meta.spin == Z)`. A violation (`QLAW_05`) occurs iff `in_explicit_z` is `true` AND `node.meta.explicit_spin` is `true` AND `node.meta.spin == S`.
- **Alias Expansion & Depth Accounting**:
  - A document-wide counter `expansions` increments by `1` on every `*alias` dereference (including nested dereferences inside aliased subtrees). Exceeding `MAX_ALIAS_EXPANSIONS` (`1_024`) triggers `QLAW_04`.
  - A recursion path set `active` tracks currently expanding anchor names; encountering `target in active` triggers `QLAW_04` (cycle).
  - In `QUIPU/2.0`, `alias_depth` increments by `1` per chained alias hop; `alias_depth + 1 > MAX_COMPOUND_SUM_DEPTH` (`10`) triggers `QLAW_09`.

### 7.3 Normative Law Definitions

| Law ID | Scope | Exact Normative Conditions |
| :--- | :--- | :--- |
| **`QLAW_01_MERKLE_SEAL`** | `1.0`, `2.0` | Active when `require_seal=True`, OR (`require_seal is None` and (`mode == sealed` or `seal is not None`)). Requires `seal is not None`, `seal.sha256 == expected.sha256`, `seal.knot == expected.knot`, and `seal.reconciled is True` over `serialize_quipu_body(doc, include_header=True)`. |
| **`QLAW_02_TOP_CORD_ARITHMETIC`** | `1.0`, `2.0` | Every `@table` `^count` MUST equal `len(rows)`; every full-column `^sum(col)` MUST reference an existing numeric/`any` column and match `_num_equal(sum, expected)`. Every node `^knots="..."` MUST parse via `decode_knots()` and, if the node value is a non-bool `int`, MUST equal that integer. |
| **`QLAW_03_COLUMN_TYPES`** | `1.0`, `2.0` | Every `@table` row MUST have `len(row) == len(columns)` and every cell MUST satisfy declared column type (`bool` is never accepted as `int` or `float`). |
| **`QLAW_04_ACYCLIC_ALIASES`** | `1.0`, `2.0` | Every `&anchor` name MUST be unique across the document; every `*alias` MUST resolve to a defined anchor without cycles and within `MAX_ALIAS_EXPANSIONS` (`1_024`). |
| **`QLAW_05_SPIN_CONTAINMENT`** | `1.0`, `2.0` | No descendant carrying explicit `~S` MAY appear inside an ancestor carrying explicit `~Z`. |
| **`QLAW_06_TAINT_NON_ESCALATION`** | `1.0`, `2.0` | Any `*alias` whose caller `eff_tier` has `rank <= 1` (`T0`/`T1`) MUST NOT reference an anchor whose `eff_tier` has `rank >= 2` (`T2`/`T3`). |
| **`QLAW_07_SAFETY_BOUNDS`** | `1.0`, `2.0` | Zero NUL bytes; UTF-8 size `<= MAX_QUIPU_BYTES` (`10_485_760`); nesting depth `<= MAX_QUIPU_DEPTH` (`32`); all floats finite. |
| **`QLAW_08_BALANCE_BOUNDS`** | `2.0` | Validates slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota` per Section 7.1, plus finite `^nether` floats. |
| **`QLAW_09_ACYCLIC_SUM_DAG`** | `2.0` | Every `@table` `^layout` (if set) MUST be in `{"banded", "seriated"}`; `spacer_indices` MUST be sorted and within `[0, len(rows)]`; alias chain depth MUST be `<= MAX_COMPOUND_SUM_DEPTH` (`10`). |
| **`QLAW_10_HEADER_TIER_AND_LINEAGE`** | `2.0` | `parent` (if set) MUST match `^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}\|none)$`; `tag`, `hub`, `^unit`, and `^wrap` (if set) MUST match `^[A-Za-z0-9_.\-/: ]{1,128}$`; when `admin_tier == working`, every `@table` MUST have `len(rows) < MAX_WORKING_ROWS` (`1_000`). |

### 7.4 Verifier Output JSON Contract

**Parsed Document Report** (`valid` is `true` iff `findings_count == 0`):

```json
{
  "valid": true,
  "verdict": "VERIFIED | VIOLATION",
  "version": "QUIPU/1.0 | QUIPU/2.0",
  "doc_id": "<str>",
  "mode": "sealed | lax",
  "knot": "quipu-<12hex> | null",
  "findings_count": 0,
  "findings": [
    {
      "law": "QLAW_XX_...",
      "path": "$ | $.seal | $.header.<attr> | $.a.b[0]",
      "severity": "error",
      "message": "<human-readable diagnostic>"
    }
  ],
  "laws_checked": ["QLAW_01_MERKLE_SEAL", "..."],
  "stats": {
    "cords": 0,
    "tables": 0,
    "anchors": 0,
    "alias_expansions": 0
  }
}
```

**Parse-Failure Report** (when `parse_quipu()` raises `QuipuSyntaxError` or NUL byte pre-check fails):

```json
{
  "valid": false,
  "verdict": "SYNTAX_ERROR | SAFETY_VIOLATION",
  "findings_count": 1,
  "findings": [
    {
      "law": "QLAW_00_SYNTAX | QLAW_07_SAFETY_BOUNDS",
      "path": "$",
      "severity": "error",
      "message": "<error detail>"
    }
  ],
  "laws_checked": []
}
```

*(QuipuSyntaxError messages containing `"Maximum nesting depth"`, `"MAX_QUIPU_DEPTH"`, `"MAX_QUIPU_BYTES"`, `"Non-finite float"`, or `"Null byte"` return `verdict="SAFETY_VIOLATION"`, `law="QLAW_07_SAFETY_BOUNDS"`, and `laws_checked=["QLAW_07_SAFETY_BOUNDS"]`; all other syntax errors return `verdict="SYNTAX_ERROR"`, `law="QLAW_00_SYNTAX"`, and `laws_checked=[]`.)*

---

## 8. CLI, Stdio JSON-RPC 2.0 MCP Server & Compatibility Policy

### 8.1 Standalone CLI Contract (`quipu`)

Invoking `quipu` with no subcommand defaults to `quipu sample --format-version 2.0`. All file paths passed to `--file` MUST pass CWE-22 path containment (resolved path MUST reside within CWD, `$HOME`, or system temp directory).

| Subcommand | Input Source | Supported Flags | Exit Code `0` | Exit Code `1` |
| :--- | :--- | :--- | :--- | :--- |
| `sample` | Built-in generator | `--format-version`, `--json` | Emits canonical sample | Error |
| `verify` | `--file` or built-in sample | `--file`, `--json` | `report["valid"] is True` | `VIOLATION`, `SYNTAX_ERROR`, `SAFETY_VIOLATION`, or I/O error |
| `from-json` | `--file` (**REQUIRED**) | `--file`, `--mode`, `--format-version`, `--json` | Emits `.quipu` wire | Missing `--file`, invalid JSON, or error |
| `to-json` | `--file` or built-in sample | `--file` | Emits indented UTF-8 JSON | Parse or I/O error |
| `bench` | `--file` (`.quipu` or `.json`) or sample | `--file`, `--json` | Emits byte/token metrics | Parse or I/O error |
| `micro` | `--file` or built-in sample | `--file`, `--json` | Emits single-line micro summary | Parse or I/O error |
| `draw` | `--file` or built-in sample | `--file`, `--max-rows` (default `8`, min `1`), `--json` | Emits visual cord diagram | Parse or I/O error |
| `upgrade` | `--file` or built-in sample | `--file`, `--admin-tier`, `--tag`, `--hub`, `--json` | Emits upgraded `QUIPU/2.0` | Parse or I/O error |
| `downgrade` | `--file` or built-in sample | `--file`, `--json` | Emits 7-law `QUIPU/1.0` | Parse or I/O error |
| `distill` | `--file` or built-in sample | `--file`, `--json` | Emits `tier=summary` rollup | Parse or I/O error |
| `mcp` | Newline-delimited JSON-RPC on `stdin` | *(none)* | Clean `stdin` EOF | Unhandled fatal error |

### 8.2 Stdio JSON-RPC 2.0 MCP Server (`quipu mcp`)

- **Transport**: Newline-delimited UTF-8 JSON-RPC 2.0 over `stdin` / `stdout`. Empty lines are ignored. Requests omitting `"id"` are treated as notifications and produce no response.
- **Protocol Constants**: `MCP_PROTOCOL_VERSION = "2024-11-05"`, `SERVER_NAME = "quipu-mcp"`, `SERVER_VERSION = "2.0.0"`.
- **Supported Methods**:
  - `initialize`: Returns `protocolVersion`, `capabilities: {"tools": {"listChanged": false}}`, and `serverInfo`.
  - `ping`: Returns `{}`.
  - `tools/list`: Returns `{"tools": [QUIPU_TOOL_SPEC]}` advertising single tool `"quipu_codec"`.
  - `tools/call`: Dispatches `name == "quipu_codec"` across all 11 actions: `verify`, `encode`, `decode`, `from_json`, `to_json`, `micro`, `draw`, `benchmark`, `upgrade`, `downgrade`, `distill`.
- **Error Handling**:
  - Protocol errors return JSON-RPC error objects: `-32700` (Parse error), `-32600` (Invalid Request), `-32601` (Method not found), `-32602` (Invalid params / unknown tool).
  - Tool execution failures (`QuipuError`, `ValueError`, `TypeError`, `JSONDecodeError`) return a normal JSON-RPC result with `isError: true` and `structuredContent: {"error": "<message>"}`.

### 8.3 Compatibility, Lifecycle & Evolution Policy

1. **Backward Compatibility (`QUIPU/1.0`)**: Every valid `QUIPU/1.0` document MUST remain parseable, verifiable under `QLAW_01`..`QLAW_07`, and seal-compatible across all `2.x` releases.
2. **Forward Strictness (`QUIPU/2.0`)**: Unknown cord decorators (`^foo`), unknown top-cord directives (`^bar(...)`), and unknown protocol versions (`~= QUIPU/3.0`) MUST fail with `QuipuSyntaxError`.
3. **Lifecycle Shims**:
   - `upgrade_quipu_to_v2(doc, *, admin_tier, tag, hub, recompute_seal=True)` promotes `1.0 -> 2.0` while recording `parent = src.parent or src_knot`.
   - `downgrade_quipu_to_v1(doc, *, recompute_seal=True)` strips `2.0` header attributes, `2.0` cord decorators, table `spacer_indices`, `layout`, and `2.0` top-cords while preserving 100% of decoded JSON payload data.
   - `distill_working_to_summary(doc, *, doc_id=None)` replaces every `QuipuTable` with a summary map `{"row_count", "column_count", "band_count", "numeric_sums"}` under `tier=summary`, `mode=sealed`, and `parent=src_knot`.
   - `link_quipus(packets, *, hub_id="HubA", doc_id="quipu.linked.bundle")` federates one or more mixed `1.0`/`2.0` packets (sorted by slot name) into a sealed `tier=summary`, `tag="linked_hub"`, `hub=hub_id` manifest containing a banded `members` `@table(slot:str, doc_id:str, version:str, mode:str, knot:str, cords:int, rows:int)` with `^count`, `^sum(cords)`, and `^sum(rows)`.

---

## 9. Security Considerations & IANA Media Type Registration

### 9.1 Safety Ceilings & CWE Mitigations

| Constant / Guard | Exact Value / Pattern | Mitigated Risk |
| :--- | :--- | :--- |
| `MAX_QUIPU_BYTES` | `10_485_760` (10 MiB) | `CWE-400` Uncontrolled Resource Consumption |
| `MAX_QUIPU_DEPTH` | `32` | Stack exhaustion / deep recursion DoS (`CWE-674`) |
| `MAX_ALIAS_EXPANSIONS` | `1_024` | `CWE-776` Recursive entity / billion-laughs expansion |
| `MAX_COMPOUND_SUM_DEPTH` | `10` | Unbounded DAG alias chain traversal |
| `MAX_WORKING_ROWS` | `1_000` (`len(rows) < 1_000` in `working`) | Memory / context saturation on uncompacted logs |
| `MAX_ASCII_CHARS` | `8_000` | Terminal / hook buffer flooding |
| Safe Tag / Unit / Wrap Regex | `^[A-Za-z0-9_.\-/: ]{1,128}$` | `CWE-20` Improper Input Validation / header injection |
| Parent Lineage Regex | `^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}\|none)$` | `CWE-20` Forged or malformed provenance links |
| CLI Path Containment | CWD, `$HOME`, or OS temp dir | `CWE-22` Improper Path Traversal |
| NUL & Non-Finite Float Guards | Reject `\x00`, `NaN`, `±Infinity` | Parser smuggling & cross-language JSON drift |

### 9.2 IANA Media Type Registration Template

- **Type name**: `application`
- **Subtype name**: `quipu`
- **Required parameters**: N/A
- **Optional parameters**: `version` (`"1.0"` or `"2.0"`, informational; wire header `~= QUIPU/<ver>` is authoritative)
- **Encoding considerations**: Binary/8-bit UTF-8 text (`charset` is always UTF-8; NUL octets `0x00` are prohibited).
- **Security considerations**: Parsers MUST enforce `MAX_QUIPU_BYTES` (`CWE-400`), `MAX_QUIPU_DEPTH`, `MAX_ALIAS_EXPANSIONS` (`CWE-776`), safe metadata character bounds (`CWE-20`), and CLI path containment (`CWE-22`). Cryptographic `=~` SHA-256 seals provide tamper detection against accidental or unauthenticated modification; they do NOT provide asymmetric sender authentication without an external signature or MAC envelope.
- **Interoperability considerations**: Strict JSON bijection (`bool != int`, finite IEEE-754 floats only) and deterministic canonical serialization (Section 4) ensure identical SHA-256 seals across implementations.
- **Published specification**: This document (`docs/SPECIFICATION.md`).
- **Applications that use this media type**: Configuration loaders, static verifiers, columnar telemetry pipelines, multi-agent MCP servers, and double-entry audit tools.
- **Additional information**:
  - Magic number(s): Optional leading UTF-8 bytes `~= QUIPU/` (`7E 3D 20 51 55 49 50 55 2F`) after optional leading whitespace/comments.
  - File extension(s): `.quipu`
  - Macintosh file type code(s): `TEXT`
- **Intended usage**: `COMMON`
- **Restrictions on usage**: None.

---

## Appendix A: Normative Interoperability Test Vectors

Conformant implementations MUST pass every positive and negative vector below. For positive sealed vectors, `verify_quipu()` MUST return `valid: true` with the exact `knot` and `sha256` shown, and `loads()` MUST equal the exact expected JSON.

### A.1 Golden Positive Test Vectors

#### Vector V1 — Minimal `QUIPU/1.0` Sealed Scalar & Map Packet

<!-- quipu-vector:pos:V1 -->
```quipu
~= QUIPU/1.0 id="vector.v1.minimal" mode=sealed

service: "auth-gateway"
port: 8443
enabled: true
ratio: 0.25
note: _
tags: ["edge", "v1"]

=~ knot="quipu-5f24bc187699" sha256="5f24bc1876994190b8c132792f4d3d393ad1731c031f7a2045ab65b2939701cd" reconciled=true
```

<!-- quipu-json:pos:V1 -->
```json
{
  "service": "auth-gateway",
  "port": 8443,
  "enabled": true,
  "ratio": 0.25,
  "note": null,
  "tags": ["edge", "v1"]
}
```

#### Vector V2 — `QUIPU/2.0` Decorators, UTF-8 Strings, `^nether` & `1E` Singular Knot

<!-- quipu-vector:pos:V2 -->
```quipu
~= QUIPU/2.0 id="vector.v2.decorators" mode=sealed tier=working tag="telemetry/core" parent="none"

label ~Z ~R @T0 @W ^wrap="utf8": "Café — 東京 🧵"
retries ~Z ~R @T0 @W ^unit="attempts" ^nether=1 ^knots="0M-0C-4D-1E": 41
canary_retries ~S ~V @T2 @D ^unit="attempts" ^nether=0.5 ^knots="0M-0C-3D-8U": 38

=~ knot="quipu-e97142506fad" sha256="e97142506fadf23dc758a9172f87ab1aa8105b9ac77b032494939a3af588d87f" reconciled=true
```

<!-- quipu-json:pos:V2 -->
```json
{
  "label": "Café — 東京 🧵",
  "retries": 41,
  "canary_retries": 38
}
```

#### Vector V3 — Banded `@table` with Spacers & Complete Top-Cord Directives

<!-- quipu-vector:pos:V3 -->
```quipu
~= QUIPU/2.0 id="vector.v2.table.full" mode=sealed tier=working tag="fiscal_reconciliation"

currency ~Z @T0: "USD"
ledger ~Z @T0 @W ^unit="usd": @table(region:str, credit:int, debt:int, guard:int) ^layout="banded" ^count=4 ^sum(credit)=1000 ^sum(credit, 0, 1)=600 ^net(credit, debt)=0 ^equal_sum(credit, debt)=1000 ^tol(credit, pct=5.0)=980 ^band(credit, ratio="3/5")=1000 ^quota(guard, pct=22.5)=4000 {
  "North" | 300 | 250 | 200
  "East" | 300 | 250 | 200
  ---
  "South" | 200 | 250 | 250
  "West" | 200 | 250 | 250
}

=~ knot="quipu-61ccbe345aa9" sha256="61ccbe345aa9190c366dcd71423b89063d0127c4d10ef7cca8f6c710d4f9b325" reconciled=true
```

<!-- quipu-json:pos:V3 -->
```json
{
  "currency": "USD",
  "ledger": [
    {"region": "North", "credit": 300, "debt": 250, "guard": 200},
    {"region": "East", "credit": 300, "debt": 250, "guard": 200},
    {"region": "South", "credit": 200, "debt": 250, "guard": 250},
    {"region": "West", "credit": 200, "debt": 250, "guard": 250}
  ]
}
```

#### Vector V4 — Acyclic `&anchor` / `*alias` Resolution Across Trust-Compatible Tiers

<!-- quipu-vector:pos:V4 -->
```quipu
~= QUIPU/2.0 id="vector.v2.aliases" mode=sealed tier=working

base_policy &std_limits ~Z @T0: {
  timeout_ms ^unit="ms": 1500
  retries: 3
}
internal_service @T1: *std_limits
external_edge @T2: *std_limits
untrusted_payload &raw_ext @T3: {
  source: "webhook"
}
quarantined_view @T2: *raw_ext

=~ knot="quipu-6c12cdd2a874" sha256="6c12cdd2a874410b8971bb7d0d367b2a45c303a95bd9f952efb296b636531ff8" reconciled=true
```

<!-- quipu-json:pos:V4 -->
```json
{
  "base_policy": {"timeout_ms": 1500, "retries": 3},
  "internal_service": {"timeout_ms": 1500, "retries": 3},
  "external_edge": {"timeout_ms": 1500, "retries": 3},
  "untrusted_payload": {"source": "webhook"},
  "quarantined_view": {"source": "webhook"}
}
```

#### Vector V5 — Headerless `mode=lax` Configuration Document

<!-- quipu-vector:pos:V5 -->
```quipu
# Headerless QUIPU config (defaults to QUIPU/1.0, id="root", mode=lax)
service: "edge-router"
replicas: 3
tls_enabled: true
timeouts: {
  connect_ms: 250,
  read_ms: 1500,
}
allow_origins: [
  "https://app.example.org",
  "https://admin.example.org",
]
```

<!-- quipu-json:pos:V5 -->
```json
{
  "service": "edge-router",
  "replicas": 3,
  "tls_enabled": true,
  "timeouts": {"connect_ms": 250, "read_ms": 1500},
  "allow_origins": [
    "https://app.example.org",
    "https://admin.example.org"
  ]
}
```

#### Vector V6 — Federated Hub Manifest (`link_quipus()`)

Generated by linking Vector V5 (`slot="config"`) and `examples/ledger_sealed.quipu` (`slot="ledger"`) under `hub_id="HubA"`:

<!-- quipu-vector:pos:V6 -->
```quipu
~= QUIPU/2.0 id="quipu.linked.bundle" mode=sealed tier=summary tag="linked_hub" hub="HubA"

hub_id: "HubA"
members: @table(slot:str, doc_id:str, version:str, mode:str, knot:str, cords:int, rows:int) ^layout="banded" ^count=2 ^sum(cords)=13 ^sum(rows)=4 {
  "config" | "root" | "QUIPU/1.0" | "lax" | "unsealed" | 10 | 0
  "ledger" | "treasury.q4.ledger" | "QUIPU/2.0" | "sealed" | "quipu-a351f60d7a7d" | 3 | 4
}

=~ knot="quipu-a876c1e66b80" sha256="a876c1e66b80ab5fd1867189ee420241206931dc7801a5b6af064b603ee6ec06" reconciled=true
```

<!-- quipu-json:pos:V6 -->
```json
{
  "hub_id": "HubA",
  "members": [
    {
      "slot": "config",
      "doc_id": "root",
      "version": "QUIPU/1.0",
      "mode": "lax",
      "knot": "unsealed",
      "cords": 10,
      "rows": 0
    },
    {
      "slot": "ledger",
      "doc_id": "treasury.q4.ledger",
      "version": "QUIPU/2.0",
      "mode": "sealed",
      "knot": "quipu-a351f60d7a7d",
      "cords": 3,
      "rows": 4
    }
  ]
}
```

### A.2 Normative Negative Test Vectors

Each minimal reproducer below MUST fail with either `QuipuSyntaxError` (reported as `QLAW_00_SYNTAX` by `verify_quipu()`) or the exact declared `QLAW_*` law ID. Escaped `\n` sequences in the table represent ASCII LF (`0x0A`).

<!-- quipu-neg-table:start -->
| Vector ID | Expected Result / Law ID | Minimal Wire Reproducer (`\n` = LF) | Failure Reason |
| :--- | :--- | :--- | :--- |
| `NEG-SYN-01` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) | `~= QUIPU/2.0 id="n.s1" mode=lax\n\nname: bare_str` | Unquoted bare identifier used as scalar value |
| `NEG-SYN-02` | `QuipuSyntaxError` (`QLAW_00_SYNTAX`) | `~= QUIPU/1.0 id="n.s2" mode=lax\n\nms ^unit="ms": 10` | `QUIPU/2.0` decorator inside explicit `QUIPU/1.0` |
| `NEG-LAW-01` | `QLAW_01_MERKLE_SEAL` | `~= QUIPU/2.0 id="n.l1" mode=sealed\n\nok: true` | Missing `=~` reconciliation seal in `mode=sealed` |
| `NEG-LAW-02` | `QLAW_02_TOP_CORD_ARITHMETIC` | `~= QUIPU/2.0 id="n.l2" mode=lax\n\nval ^knots="0M-0C-0D-5U": 4` | Base-10 knot parity `5` disagrees with integer `4` |
| `NEG-LAW-03` | `QLAW_03_COLUMN_TYPES` | `~= QUIPU/2.0 id="n.l3" mode=lax\n\nt: @table(n:int) {\n  true\n}` | Boolean `true` rejected in `int` column |
| `NEG-LAW-04` | `QLAW_04_ACYCLIC_ALIASES` | `~= QUIPU/2.0 id="n.l4" mode=lax\n\na &loop: *loop` | Direct cyclic alias reference |
| `NEG-LAW-05` | `QLAW_05_SPIN_CONTAINMENT` | `~= QUIPU/2.0 id="n.l5" mode=lax\n\nbox ~Z: {\n  x ~S: 1\n}` | Explicit mutable `~S` nested inside explicit `~Z` |
| `NEG-LAW-06` | `QLAW_06_TAINT_NON_ESCALATION` | `~= QUIPU/2.0 id="n.l6" mode=lax\n\next &u @T3: "raw"\nok @T0: *u` | Trusted `@T0` cord aliases untrusted `@T3` anchor |
| `NEG-LAW-07` | `QLAW_07_SAFETY_BOUNDS` | `~= QUIPU/2.0 id="n.l7" mode=lax\n\nx: 1e309` | Non-finite float overflow rejected (`SAFETY_VIOLATION`) |
| `NEG-LAW-08` | `QLAW_08_BALANCE_BOUNDS` | `~= QUIPU/2.0 id="n.l8" mode=lax\n\nt: @table(v:int) ^tol(v, pct=5.0)=100 {\n  120\n}` | Actual `120` breaches upper tolerance bound `105.0` |
| `NEG-LAW-09` | `QLAW_09_ACYCLIC_SUM_DAG` | `~= QUIPU/2.0 id="n.l9" mode=lax\n\nt: @table(v:int) ^layout="bad" {\n  1\n}` | Unsupported `@table` layout value `"bad"` |
| `NEG-LAW-10` | `QLAW_10_HEADER_TIER_AND_LINEAGE` | `~= QUIPU/2.0 id="n.l10" mode=lax parent="BAD"\n\nok: true` | Malformed `parent` lineage attribute |
<!-- quipu-neg-table:end -->

---

## Appendix B: Andean Epigraphic Heritage Glossary

All wire tokens and public API symbols in `QUIPU/2.0` use concise English. The historical terms below document the Andean *khipu* mechanisms that inspired the protocol's data structures:

| Archival Term | Origin | One-Sentence Explanation | `QUIPU/2.0` Equivalent |
| :--- | :--- | :--- | :--- |
| *khipu / quipu* | Quechua | A knotted-cord Andean recording instrument used for quantitative ledgers, administrative censuses, and narrative archives. | `QUIPU/2.0` / `.quipu` |
| *kayte* | Quechua | A categorical marker or rubric cord tied to the primary cord to identify the subject of a cord group. | `tag="..."` |
| *canuto* | Spanish | A tightly wound sleeve of colored thread wrapping a cord segment to carry qualitative provenance or encoding metadata. | `^wrap="..."` |
| *inokatha / nakku* | Aymara / Quechua | A double-entry reconciliation mechanism checking paired credit and obligation cords for zero or target net balance. | `^net(credit, debt)` |
| *yapa / qhincha* | Quechua | The contrast between a permissible small positive margin (*yapa*) and an unacceptable deficit or overrun (*qhincha*). | `^tol(col, pct=N)` |
| *waranqa* | Quechua | A decimal administrative unit of 1,000 households that bounded working-tier ledger granularity before rollup. | `MAX_WORKING_ROWS = 1_000` |
| *yupana* | Quechua | A stepped positional counting tray that quantized numbers across discrete logarithmic magnitude tiers. | `SCALE_BUCKETS`, `quantize_bucket()` |
| *khipus enlazados* | Spanish | Physically tied companion khipus federated under a shared supervisory cord for cross-archive reconciliation. | `link_quipus(..., hub_id=...)` |
| *chakana* (knotless spacer) | Quechua | An unknotted spacing interval separating banded cord moieties along the primary cord. | `---` spacer & `^band` |
| *hanan / hurin* (recto / verso) | Quechua | Paired complementary attachment orientations distinguishing upper/primary cords from lower/verification cords. | `~R` / `~V` |
| *Z / S spin* | Epigraphy | Opposite directional fiber ply twists signaling authoritative canonical cords versus subsidiary mutable cords. | `~Z` / `~S` |
| *nudo en ocho* (figure-8 knot) | Spanish | A distinct figure-8 knot used exclusively in the units position to mark the singular value `1`. | `1E` (`figure_eight_unit=True`) |
