# QUIPU Syntax, CLI, MCP & Verification Law Reference

## 1. Wire Framing & Header Governance

```text
~= QUIPU/2.0 id="svc.telemetry" mode=sealed tier=working tag="metrics" parent="none" hub="HubA"

key_name &anchor ~Z ~R @T0 @W ^unit="tokens" ^wrap="utf8" ^nether=1 ^knots="0M-0C-4D-1E": 41

=~ knot="quipu-<12hex>" sha256="<64hex>" reconciled=true
```

- **Header (`~=`)**:
  - Required version: `QUIPU/2.0` (default) or `QUIPU/1.0`.
  - Standard attributes: `id="..."` (default `"root"`), `mode=sealed|lax` (`sealed` with header, `lax` when headerless).
  - `2.0`-only attributes: `tier=working|summary|hybrid`, `tag="..."`, `parent="<prefix>-<12hex>|none"`, `hub="..."`.
  - Unrecognized header attributes are ignored in `2.0` and omitted on canonical serialization; `tier`/`tag`/`parent`/`hub` fail in `QUIPU/1.0`.
- **Headerless documents**: Default to `QUIPU/1.0` (`mode=lax`, `id="root"`) and auto-promote to `QUIPU/2.0` only when `2.0` decorators (`~R`/`~V`, `@W`/`@D`, `^unit`, `^wrap`, `^nether`) or `2.0` table features (`---`, `^layout`, `2.0` top-cords) appear. (`1E` inside `^knots` alone does NOT promote.)

## 2. Canonical Decorator Order

Producers emit active decorators on a node in fixed order (`~Z` and `@T0` omitted unless explicitly annotated):

1. `&anchor` — Unique node identifier referenced via `*anchor` (`<= 1_024` expansions, `<= 10` chain depth in `2.0`).
2. `~Z` / `~S` — Canonical immutable (`~Z`) vs mutable (`~S`) spin.
3. `~R` / `~V` — Primary (`~R`) vs shadow/canary (`~V`) branch side (`2.0`).
4. `@T0..@T3` — Taint/trust hierarchy (`T0` SSOT, `T1` workspace, `T2` external, `T3` untrusted).
5. `@W` / `@D` — Credit/asset (`@W`) vs debit/obligation (`@D`) accounting polarity (`2.0`).
6. `^unit="..."` — Physical/semantic unit (`^[A-Za-z0-9_.\-/: ]{1,128}`, `2.0`).
7. `^wrap="..."` — Codec or compliance wrapper tag (`2.0`).
8. `^nether=<num>` — Finite auxiliary integer or float weight (`2.0`).
9. `^knots="0M-0C-4D-1E"` — Base-10 integer parity (`1E` singular marker via `figure_eight_unit=True`).

Decorators MAY appear before `:`, after `:`, or split across both sides (never repeated on the same category).

## 3. Typed `@table(...)` & Top-Cord Directives

- **Column types**: `any`, `str`, `int`, `float`, `bool`, `str?`, `int?`, `float?`, `bool?` (`bool` is never valid as `int` or `float`).
- **`auto_table=True`**: Compiles lists of `>= 2` maps with `1..32` identical ordered bare keys and valid scalars into `@table`; mixed numeric (`int` + `float`) columns infer as `any`; nullable homogeneous columns infer as `T?`; auto-emits `^count` plus up to `3` strict `int` `^sum` directives.
- **Top-Cords** (accepted before `{` or after `}`):

| Directive | Version | Enforced Semantic |
| :--- | :--- | :--- |
| `^count=N` | `1.0`, `2.0` | `len(rows) == N` (`QLAW_02`) |
| `^sum(col)=V` | `1.0`, `2.0` | Sum of numeric cells in `col` equals `V` (`1e-9` float tol, `QLAW_02`) |
| `^sum(col, s, e)=V` | `2.0` | Inclusive slice `[s, e]` sum equals `V` (`QLAW_08`) |
| `^net(c1, c2)=N` | `2.0` | `sum(c1) - sum(c2) == N` (`QLAW_08`) |
| `^equal_sum(c1, c2)=P` | `2.0` | `sum(c1) == P` and `sum(c2) == P` (`QLAW_08`) |
| `^tol(col, pct=T)=N` | `2.0` | `0 < T <= 100` (default `5.0`) and `N <= sum(col) <= N * (1 + T / 100)` (`QLAW_08`) |
| `^band(col, ratio="R")=V` | `2.0` | Requires `---` spacer; `R` in `1/2, 1/3, 2/3, 2/5, 3/5` (default `"1/2"`), `sum(col) == V > 0` (`QLAW_08`) |
| `^quota(col, pct=P)=Pop` | `2.0` | `0 < P <= 100` (default `22.5`) and `sum(col) / (P / 100) ≈ Pop` (`QLAW_08`) |
| `^layout="banded"\|"seriated"` | `2.0` | Table banding mode paired with sorted `---` spacers (`QLAW_09`) |

## 4. Static Verification Laws (`QLAW_01`..`QLAW_10`)

- **Pre-AST Safety Routing**: `QuipuSyntaxError` containing `"Maximum nesting depth"`, `"MAX_QUIPU_DEPTH"`, `"MAX_QUIPU_BYTES"`, `"Non-finite float"`, or `"Null byte"` returns `verdict="SAFETY_VIOLATION"` with `QLAW_07_SAFETY_BOUNDS`; other syntax failures return `verdict="SYNTAX_ERROR"` (`QLAW_00_SYNTAX`).
- **`1.0` (`QLAW_01`..`QLAW_07`)**: Merkle seal (`=~`), `^count`/`^sum`/`^knots`, table column types, acyclic `&`/`*` aliases (`<= 1_024`), explicit `~Z` spin containment, `@T0`/`@T1` taint non-escalation, safety ceilings (`10_485_760` bytes, depth `<= 32`, zero NUL, finite floats).
- **`2.0` (`+ QLAW_08`..`QLAW_10`)**: Balance/slice/tolerance/band/quota bounds, `^layout`/spacer ordering/alias chain depth `<= 10`, safe `tag`/`hub`/`^unit`/`^wrap`, valid `parent`, and `< 1_000` rows in `tier=working`.

## 5. CLI & Stdio MCP Contract

- **CLI (`quipu <action>`)**: `sample`, `verify`, `from-json`, `to-json`, `bench`, `micro`, `draw` (`--max-rows`), `upgrade` (`--admin-tier`, `--tag`, `--hub`), `downgrade`, `distill`, `mcp`. Default action is `sample --format-version 2.0`.
- **MCP (`quipu mcp`, protocol `2024-11-05`)**: Single tool `quipu_codec` with `action` in `verify`, `encode`, `decode`, `from_json`, `to_json`, `micro`, `draw`, `benchmark`, `upgrade`, `downgrade`, `distill`.
