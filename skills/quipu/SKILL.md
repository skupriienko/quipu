---
name: quipu
description: Encode, decode, verify, compact, and visualize QUIPU/2.0 and QUIPU/1.0 (.quipu) structured data, typed @table ledgers, double-entry arithmetic invariants, taint/mutability decorators, and SHA-256 tamper seals via the quipu CLI, Python API, or Stdio MCP server. Use when working with .quipu files, replacing fragile JSON/YAML/CSV configs or tabular agent tool payloads, auditing columnar sums/quotas/tolerances, or sealing provenance-tracked artifacts.
license: MIT
---

# QUIPU Agent Skill (`QUIPU/2.0` & `QUIPU/1.0`)

Use `quipu` to give AI/LLM agents lossless JSON isomorphism alongside inline typed tables, double-entry arithmetic checks, provenance/taint tiers, and deterministic SHA-256 tamper seals in zero-dependency `.quipu` files.

## Prerequisites & Setup

Ensure Python `3.10+` is available, then install or verify `quipu`:

```bash
pip install "git+https://github.com/skupriienko/quipu.git"
# Or from a local clone:
pip install -e .
quipu verify --json
```

Optional MCP server setup (Claude Desktop, Cursor, Windsurf, Cline, Zed): run `quipu mcp` (protocol `2024-11-05`, exposes tool `quipu_codec`).

## When to Use

- Reading, authoring, validating, or troubleshooting `.quipu` configs, ledgers, telemetry receipts, or hub manifests.
- Compacting repetitive JSON arrays into column-typed `@table(...)` payloads that fit under 8 KB CLI/hook limits without key repetition.
- Enforcing static arithmetic checks (`^count`, `^sum`, slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota`) before downstream code runs.
- Separating immutable source-of-truth parameters (`~Z @T0`) from mutable overrides (`~S`) or untrusted external inputs (`@T2`/`@T3`).
- Chaining provenance across artifacts via `parent="<prefix>-<12hex>"` (`distill`, `upgrade`, `link_quipus`).

## When Not to Use

- Plain Markdown prose responses or summaries written for end users.
- Raw binary media, images, or arbitrary opaque blobs (store references/checksums instead).
- Full 6-plane multi-agent DAG orchestration with file read/write lock sets (use a dedicated workflow state format).

## Task Routing & Ordered Workflow

Load [references/syntax-and-laws.md](references/syntax-and-laws.md) for full grammar and law tables, or [references/agent-workflows-and-antipatterns.md](references/agent-workflows-and-antipatterns.md) for runnable recipes and anti-pattern fixes.

| Task | Primary Tool / API | Ordered Action |
| :--- | :--- | :--- |
| **Inspect / Render** | `quipu draw --file P` / `quipu.draw()` | Render ASCII cord diagram + upward top-cords (`max_rows=8`, `MAX_ASCII_CHARS=8_000`) |
| **Verify Packet** | `quipu verify --file P --json` / `quipu.verify()` | Check `valid`, `verdict`, and all 7 (`1.0`) or 10 (`2.0`) static laws |
| **JSON <-> QUIPU** | `quipu from-json --file data.json` / `quipu to-json --file P` | Compile uniform dicts (`>= 2`) to `@table` via `auto_table=True` and seal |
| **Author Sealed Packet** | `quipu.dumps(data, doc_id=..., mode="sealed")` | Emit canonical body and compute exact `=~` SHA-256 footer |
| **Compact / Upgrade** | `quipu distill` / `quipu upgrade` / `quipu downgrade` | Shrink `< 1000`-row `working` tables to `summary` or bridge `1.0 <-> 2.0` |
| **Federate Swarm** | `quipu.link_quipus(packets, hub_id=...)` | Merge mixed `1.0`/`2.0` receipts into one signed `hub` table |
| **MCP Tooling** | `quipu_codec` (`verify`, `encode`, `decode`, `from_json`, `to_json`, `micro`, `draw`, `benchmark`, `upgrade`, `downgrade`, `distill`) | Call via Stdio JSON-RPC 2.0 (`quipu mcp`) |

## Critical Rules for AI Agents

1. **Never hand-invent SHA-256 seals**: Always generate `=~ knot="quipu-<12hex>" sha256="<64hex>" reconciled=true` via `quipu.dumps()`, `quipu.dump_quipu(doc, recompute_seal=True)`, `quipu from-json`, or `quipu_codec`.
2. **Always double-quote strings**: Bare identifiers in value or `@table` cell positions fail with `QuipuSyntaxError`; only `true`, `false`, `null`, and `_` (canonical null) are bare value literals.
3. **Keep types strict (`bool != int`)**: In `@table(col:type)`, booleans never coerce to `int` or `float`, and `null`/`_` requires a nullable type suffix (`str?`, `int?`, `float?`, `bool?`, or `any`).
4. **Respect explicit spin containment (`~Z` vs `~S`)**: Never place explicit `~S` inside an ancestor annotated with explicit `~Z` (`QLAW_05_SPIN_CONTAINMENT`).
5. **Respect taint non-escalation (`@T0..@T3`)**: Cords at `@T0` or `@T1` MUST NOT `*alias` anchors defined inside `@T2` or `@T3` (`QLAW_06_TAINT_NON_ESCALATION`).
6. **Guard `tier=working` row bounds**: Tables inside `tier=working` MUST stay strictly `< 1_000` rows (`MAX_WORKING_ROWS`); call `distill_working_to_summary()` before exceeding the limit.
7. **Keep `QUIPU/1.0` clean**: Inside `~= QUIPU/1.0`, omit `2.0` extensions (`tier`, `tag`, `parent`, `hub`, `~R`/`~V`, `@W`/`@D`, `^unit`, `^wrap`, `^nether`, `---`, `^layout`, `^net`, `^tol`, `^band`, `^quota`, slice `^sum`).
8. **Format `parent` cleanly**: Under `QUIPU/2.0`, `parent` MUST match `^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}|none)$`.

## Failure Diagnostics (`QLAW_00`..`QLAW_10`)

| Verdict / Law | Root Cause | Fix |
| :--- | :--- | :--- |
| `SYNTAX_ERROR` (`QLAW_00_SYNTAX`) | Unquoted string, duplicate key, bad number (`01`), or `2.0` token in `1.0` | Quote strings, deduplicate keys, upgrade header to `QUIPU/2.0` |
| `SAFETY_VIOLATION` (`QLAW_07_SAFETY_BOUNDS`) | NUL byte `\x00`, non-finite float (`1e309`), depth `> 32`, size `> 10 MiB` | Remove NUL/NaN/Inf, flatten depth `<= 32` |
| `QLAW_01_MERKLE_SEAL` | Missing/stale `=~` seal after edits in `mode=sealed` | Re-seal with `quipu.dump_quipu(doc, recompute_seal=True)` |
| `QLAW_02_TOP_CORD_ARITHMETIC` | `^count`, full `^sum`, or `^knots` disagrees with data | Fix integer/rows or recompute aggregates (`encode_knots`) |
| `QLAW_03_COLUMN_TYPES` | Row arity mismatch or wrong cell type (`true` in `int`) | Align pipe-separated cells and declared column types |
| `QLAW_04_ACYCLIC_ALIASES` | Undefined `*alias`, duplicate `&anchor`, cycle, or `> 1_024` expansions | Define unique acyclic anchors under budget |
| `QLAW_05_SPIN_CONTAINMENT` | Explicit `~S` child inside explicit `~Z` parent | Move mutable override outside the `~Z` block |
| `QLAW_06_TAINT_NON_ESCALATION` | `@T0`/`@T1` cord references `@T2`/`@T3` anchor | Downgrade caller tier or sanitize/copy verified data |
| `QLAW_08_BALANCE_BOUNDS` | Slice `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, or `^quota` failure | Reconcile debits/credits, `---` band split, or tolerance |
| `QLAW_09_ACYCLIC_SUM_DAG` | Bad `^layout`, unsorted `---` spacers, or alias chain `> 10` | Use `"banded"`/`"seriated"` and shorten alias chain |
| `QLAW_10_HEADER_TIER_AND_LINEAGE` | Invalid `parent`/`tag`/`hub`/`^unit`/`^wrap`, or `working >= 1_000` rows | Fix metadata syntax or run `quipu distill` |

## Output Contract

When modifying or generating `.quipu` artifacts for a user or downstream agent:
1. Run `quipu verify --file <artifact> --json` (or `quipu.verify(wire)`) and confirm `valid: true` (`findings_count == 0`).
2. Report the `version`, `mode`, `knot`, and `laws_checked` count (`7` or `10`), plus any compacted row/byte savings when distilling or converting from JSON.

## Limitations

- SHA-256 `=~` seals detect accidental or unauthenticated modifications; they do **not** provide asymmetric sender authentication without an external signature or MAC envelope.
- `quipu bench --file` auto-detects `.quipu` only when leading text begins with `~=`; pass a headed document or `.json` file to `bench`.
- CLI `--file` paths are restricted by CWE-22 containment to CWD, `$HOME`, or the OS temp directory.
