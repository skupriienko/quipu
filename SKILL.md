---
name: quipu
description: Zero-dependency QUIPU/2.0 & QUIPU/1.0 (.quipu) data serialization, columnar arithmetic verification, JSON isomorphism, CLI, and Stdio MCP server.
---

# QUIPU Format & Codec Skill

Use `quipu` whenever serializing, validating, compacting, or exchanging structured records and provenance-annotated payloads in `.quipu` (`QUIPU/2.0` and `QUIPU/1.0`) format.

## Format Highlights

- **Headers & Seals**: `~= QUIPU/2.0 id="..." mode=sealed` with optional `tier=working|summary|hybrid`, `tag="..."`, `parent="quipu-..."`, `hub="..."` and trailing SHA-256 knot footer `=~ knot="quipu-<12hex>" sha256="..." reconciled=true`.
- **Typed Columnar Tables**: `@table(col:type, ...)` with Top-Cord invariants (`^count`, `^sum`, slice `^sum`, `^tol`, `^net`, `^equal_sum`, `^band`, `^quota`, `^layout`) and `---` row spacers.
- **Cord Decorators**: Spin (`~Z` immutable, `~S` mutable), branch side (`~R` primary, `~V` shadow), trust tier (`@T0`..`@T3`), polarity (`@W` credit, `@D` debt), units/wrappers (`^unit`, `^wrap`, `^nether`), bounded DAG aliases (`&anchor` / `*alias`), and positional base-10 knots (`^knots="0M-0C-0D-3U"`).

## Python API

```python
import quipu

# Lossless JSON / Python isomorphism
wire = quipu.dumps({"service": "edge-gateway", "items": [{"id": 1, "n": 10}, {"id": 2, "n": 20}]})
data = quipu.loads(wire)

# Static verification (7 laws for QUIPU/1.0, 10 laws for QUIPU/2.0)
report = quipu.verify(wire)
assert report["valid"]

# Compatibility & compaction
v1_doc = quipu.downgrade_quipu_to_v1(wire)
summary = quipu.distill_working_to_summary(wire)
```

## CLI Commands

```bash
quipu sample --format-version 2.0
quipu verify --file payload.quipu --json
quipu from-json --file data.json --mode sealed
quipu to-json --file payload.quipu
quipu bench --file data.json --json
quipu micro --file payload.quipu
quipu upgrade --file v1.quipu --admin-tier working --tag release
quipu downgrade --file v2.quipu
quipu distill --file working.quipu
quipu mcp
```

## Stdio MCP Server (`quipu mcp`)

Configure `quipu mcp` as a zero-dependency Stdio JSON-RPC 2.0 MCP server exposing tool `quipu_codec`:

- **Actions**: `verify`, `encode`, `decode`, `from_json`, `to_json`, `micro`, `benchmark`, `upgrade`, `downgrade`, `distill`.
- **Parameters**: `quipu_text`, `json_text`, `data`, `doc_id`, `mode`, `version`, `admin_tier`, `tag`, `hub`, `auto_table`, `require_seal`.
