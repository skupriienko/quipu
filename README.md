# quipu

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-10b981.svg)](#installation)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Types: Mypy Strict](https://img.shields.io/badge/types-mypy%20strict-blue.svg)](https://mypy-lang.org/)

> **Standalone `QUIPU/2.0` & `QUIPU/1.0` (`.quipu`) Data, Columnar Arithmetic & Cryptographic Provenance Standard**  
> Zero-dependency, JSON-isomorphic serialization format combining human-ergonomic configs, zero-key-repetition typed tables, inline double-entry verification, taint/mutability metadata, and built-in SHA-256 tamper seals.

---

## Purpose & Target Use Cases

JSON, YAML, and TOML each solve a narrow slice of structured data exchange while leaving recurring reliability, security, and verification gaps open in modern AI-assisted engineering:

1. **Hazard-Free Application & Agent Configs (`mode=lax`)**: JSON forbids `#` comments and trailing commas; YAML 1.2 suffers from implicit type coercion (`yes`/`no` -> bool) and exponential alias-bomb DoS (`CWE-776`). Headerless `.quipu` supports `#` comments, bare keys, and trailing commas while guaranteeing **100% lossless bijection with JSON**.
2. **Sub-8KB CLI Hook & MCP Tool Envelopes (`@table` + `distill`)**: Many coding-agent CLI harnesses silently truncate hook or tool outputs above ~8,000 characters, and JSON wastes tokens repeating keys across uniform rows. `@table(...)` eliminates key repetition while validating column types (`bool != int`), and `distill_working_to_summary()` + `render_quipu_micro()` collapse `working` tables (`<= 1000` rows) into sub-8KB `summary` receipts or single-line fingerprints.
3. **Tamper-Evident Security Scan, TDD & Review Receipts (`=~`)**: Automated security scanners, red-green-refactor TDD verifiers, and architecture rationale checkers stamp pass/fail receipts with deterministic SHA-256 knots (`=~ knot="quipu-<12hex>"`) and `^count=0` violation invariants checked in sub-millisecond time before merge or deployment.
4. **Curated CWE / OWASP Vulnerability & Rule Vaults (`@table` + `QLAW_03`)**: Maintaining multi-hundred-row static-analysis rule catalogs and remediation matrices as diff-friendly `@table` grids ensures accidental row deletion, column shifts, or severity-plane drift trip `QLAW_03` (`^count`, `^sum`) immediately in CI.
5. **Multi-Agent Parallel Fan-Out & Hub Handoffs (`link_quipus`)**: Independent worker agents (researcher, implementer, verifier) emit small, self-contained sealed packets (`1.0` or `2.0`) that a coordinator merges into one federated `hub` manifest via `link_quipus()`, preserving end-to-end cryptographic provenance without context-window bloat.
6. **Prompt-Injection & RAG Taint Quarantine (`@T0..@T3`, `~Z`/`~S`)**: Labeling system policies (`~Z @T0` immutable SSOT) alongside untrusted web/user/MCP tool payloads (`~S @T3`) prevents accidental mutation (`QLAW_05`) and enforces taint non-escalation (`QLAW_06`) so trusted nodes can never reference untrusted anchors.
7. **Content-Addressed Context Cartridges & Cross-Artifact Lineage (`parent`)**: Pinning distilled reference packs, episodic agent logs, and session checkpoints by `quipu-<12hex>` seals lets runtimes verify cache freshness in $O(1)$ and trace derived summaries back to exact upstream artifacts via cross-artifact `parent` links (`<prefix>-<12hex>` such as `quipu-...`, `bundle-...`, `trace-...`, or `"none"`).
8. **Double-Entry FinOps, Token Budgets & Ranked Scorecards (`@W`/`@D`, `^net`, `^tol`)**: Financial ledgers, LLM token budgets, and prioritized triage tables declare credit/debt polarity (`@W`/`@D`), conservation equations (`^net`, `^equal_sum`), overrun guardrails (`^tol`), contiguous rank sums (`^sum(rank)`), and zero-blocker invariants (`^sum(blockers)=0`) to catch silent arithmetic hallucinations before downstream APIs execute.
9. **Primary / Canary Rollout Twins (`~R`/`~V` & `^unit`)**: Active production parameters (`~R`) and shadow/canary verification twins (`~V`) live side-by-side under explicit physical/semantic units (`^unit="ms"`, `^unit="usd"`, `^unit="tokens"`) without inventing ad-hoc `"_shadow"` key suffixes or mismatching milliseconds vs seconds.
10. **Self-Auditing Workspace & Package Inventories (`^count` + `^sum`)**: Release engineering scripts emit dual-ledger artifact manifests tracking file paths, versions, and SHA-256 checksums backed by inline `^count` and `^sum` assertions to catch silent workspace drift before publishing.

---

## Format Comparison

| Capability | **QUIPU/2.0** | **JSON** | **JSONC / 5** | **YAML 1.2** | **TOML 1.0** | **CSV / TSV** | **XML** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Comments (`#`)** | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Lossless JSON Bijection** | ✅ | ✅ | ⚠️ `NaN`/hex | ⚠️ `yes`/`no` | ⚠️ types | ❌ flat | ⚠️ lossy |
| **Typed Columnar `@table`** | ✅ `bool!=int` | ❌ | ❌ | ❌ | ⚠️ verbose | ⚠️ untyped | ❌ |
| **Inline Math & Double-Entry** | ✅ `^sum`/`^net` | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ XSD |
| **Built-in SHA-256 Seal (`=~`)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ DSig |
| **Bounded Safe Aliases** | ✅ `<=1024` | ❌ | ❌ | ⚠️ DoS risk | ❌ | ❌ | ⚠️ XXE risk |
| **Mutability & Trust Tiers** | ✅ `~Z`/`@T0..3` | ❌ | ❌ | ⚠️ untyped | ❌ | ❌ | ⚠️ attrs |
| **Tiered Rollup & Hub Link** | ✅ `tier`/`hub` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Zero-Dep Stdlib Codec** | ✅ `0` deps | ✅ | ❌ | ❌ | ⚠️ read-only | ✅ flat | ⚠️ parser |

> **Legend:** ✅ Built-in / Native · ⚠️ Partial, external schema, or safety caveat · ❌ Not supported

---

## Architecture

```text
  QUIPU/1.0 Wire (~= QUIPU/1.0) ──▶ parse() [7 Laws: QLAW_01..07] ──┐
                                                                    ▼
  QUIPU/2.0 Wire (~= QUIPU/2.0) ──▶ parse() [10 Laws: QLAW_01..10] ─┴─▶ Unified QuipuDocument AST
                                                                          │
        ┌─────────────────────────────────────────────────────────────────┼──────────────────────┐
        ▼                                 ▼                               ▼                      ▼
  Python / JSON Data            Version & Tier Shims             Federation Hub         Static Verifier
  • loads() / load()            • upgrade_quipu_to_v2()          • link_quipus()        • verify() [10 Laws]
  • dumps() / dump()            • downgrade_quipu_to_v1()        • hub="..."            • =~ SHA-256 Knot Seal
  • 100% lossless bijection     • distill_working_to_summary()   • mixed 1.0 + 2.0      • 7-bit / 14-bit micro
```

---

## Primitives Summary (What & Why)

Every QUIPU decorator, directive, and register strips cleanly during `loads()`/`load()` so standard JSON consumers receive plain Python dicts, lists, and scalars, while validators and agents get machine-checkable guarantees in-band:

| Primitive | Syntax & AST Field | What It Is & Why It Is Needed |
| :--- | :--- | :--- |
| **Spin / Mutability** | `~Z` / `~S` (`CordMeta.spin`) | Immutable canonical SSOT (`~Z`) vs mutable runtime/override (`~S`). Prevents accidental policy or config mutation inside locked containers (`QLAW_05`). |
| **Branch Attachment** | `~R` / `~V` (`CordMeta.attachment`) | Primary active branch (`~R`) vs shadow/canary/verification branch (`~V`). Co-locates live and canary/audit twins atomically without brittle `"foo_shadow"` keys. |
| **Trust Tiers** | `@T0`..`@T3` (`CordMeta.tier`) | Provenance trust hierarchy from `T0` (verified SSOT) to `T3` (untrusted user/network input). Enforces taint non-escalation (`QLAW_06`) so trusted nodes cannot alias untrusted anchors. |
| **Accounting Polarity** | `@W` / `@D` (`CordMeta.polarity`) | Asset/credit/budget (`@W`) vs obligation/debt/charge (`@D`). Makes financial, token-budget, and quota cords self-describing for double-entry auditing without external schemas. |
| **Physical / Semantic Unit** | `^unit="..."` (`CordMeta.unit`) | Explicit unit annotation (`"usd"`, `"ms"`, `"bytes"`, `"tokens"`). Prevents unit-mismatch bugs (ms vs seconds, cents vs dollars) without boxing decoded numbers. |
| **Protocol / Wrapper Tag** | `^wrap="..."` (`CordMeta.wrap`) | Codec or compliance wrapper tag (`"hmac_sha256"`, `"base64"`, `"semver"`, `"pii_redacted"`). Carries encoding provenance out-of-band without wrapper objects. |
| **Auxiliary Checksum Weight** | `^nether=<num>` (`CordMeta.nether`) | Secondary numeric epoch, fee weight, or reconciliation delta attached to a node. Transports audit metadata without altering the decoded scalar value. |
| **Base-10 Knots & `1E`** | `^knots="0M-0C-4D-1E"` (`CordMeta.knots`) | Positional decimal parity (`M-C-D-U`) plus `1E` figure-eight singular/sentinel marker (`encode_knots(..., figure_eight_unit=True)`). Catches silent integer corruption or LLM digit hallucinations (`QLAW_02`). |
| **Bounded DAG Reuse** | `&anchor` / `*alias` (`CordAlias`) | Acyclic node reuse capped at `<= 1024` expansions and `<= 10` chain depth (`QLAW_04`, `QLAW_09`). Eliminates repetition without YAML's billion-laughs DoS (`CWE-776`). |
| **Typed Tables & Top-Cords** | `@table(...)`, `---`, `^layout`, `^count`, `^sum`, `^net`, `^equal_sum`, `^tol`, `^band`, `^quota` | Columnar typed tables with row spacers (`---`), slice sums `^sum(col, s, e)`, double-entry `^net`/`^equal_sum`, overrun guard `^tol`, spacer ratio `^band`, and cohort projection `^quota` (`QLAW_03`, `QLAW_08`). |
| **Header Governance & Seal** | `~=`, `mode`, `tier`, `tag`, `parent`, `hub`, `=~` | Enforces `MAX_WORKING_ROWS = 1000` context bounds (`working` vs `summary` vs `hybrid`), cross-artifact `parent` lineage (`<prefix>-<12hex>` \| `none`), `hub` federation, and SHA-256 tamper evidence (`QLAW_01`, `QLAW_10`). |
| **Registers & Quantization** | `encode_7bit`, `encode_14bit`, `SCALE_BUCKETS`, `quantize_bucket`, `project_quota_population`, `render_quipu_micro`, `MAX_ASCII_CHARS` | Compact bit vectors, logarithmic scale buckets (`1..1000`), single-line micro fingerprints, and 8KB-bounded CLI cord diagrams (`MAX_ASCII_CHARS = 8_000`) for $O(1)$ routing and capacity projection without full AST parsing. |

---

## Installation

`quipu` requires **Python 3.10+** and has **zero runtime dependencies**.

```bash
# Install directly from GitHub
pip install "git+https://github.com/skupriienko/quipu.git"

# Or clone and install in editable mode
git clone https://github.com/skupriienko/quipu.git
cd quipu
pip install -e .
```

---

## Quick Python API

```python
import io
import quipu

# 1. Lossless JSON / Python serialization & deserialization
payload = {
    "service": "edge-gateway",
    "metrics": [
        {"stage": "lint", "tokens": 42, "ok": True},
        {"stage": "test", "tokens": 118, "ok": True},
    ],
}
wire = quipu.dumps(payload, doc_id="ci.receipt", mode="sealed")
assert quipu.loads(wire) == payload

# 2. Stream I/O (mirrors json.dump / json.load)
buf = io.StringIO()
quipu.dump(payload, buf, doc_id="ci.receipt")
buf.seek(0)
assert quipu.load(buf) == payload

# 3. Parse into typed AST & run 10-law static verification
doc = quipu.parse(wire)
report = quipu.verify(wire)
assert report["valid"] is True
assert len(report["laws_checked"]) == 10  # 7 laws for QUIPU/1.0, 10 for QUIPU/2.0

# 4. Visual CLI cord diagram & bit-register fingerprint
print(quipu.draw(wire))
print(quipu.render_quipu_micro(doc))

# 5. Version compatibility, distillation & multi-packet federation
v1_doc = quipu.downgrade_quipu_to_v1(wire)
v2_doc = quipu.upgrade_quipu_to_v2(v1_doc, admin_tier="working", tag="ci")
summary_doc = quipu.distill_working_to_summary(v2_doc)
hub_doc = quipu.link_quipus({"legacy": v1_doc, "rollup": summary_doc}, hub_id="HubA")
```

---

## CLI Usage

```bash
# Print a canonical QUIPU/2.0 (or QUIPU/1.0) sample packet
quipu sample --format-version 2.0

# Verify all 10 static laws & SHA-256 seal (JSON report optional)
quipu verify --file examples/ledger_sealed.quipu --json

# Convert JSON <-> .quipu
quipu from-json --file data.json --mode sealed --format-version 2.0
quipu to-json --file examples/telemetry_banded.quipu

# Benchmark bytes and token savings vs JSON
quipu bench --file examples/telemetry_banded.quipu

# Render a visual ASCII/Unicode cord diagram in the terminal
quipu draw --file examples/telemetry_banded.quipu --max-rows 8
quipu draw --file examples/ledger_sealed.quipu

# Emit compact 7-bit / 14-bit micro summary line
quipu micro --file examples/telemetry_banded.quipu

# Upgrade 1.0 -> 2.0, downgrade 2.0 -> 1.0, or distill working -> summary
quipu upgrade --file examples/legacy_v1.quipu --admin-tier working --tag release
quipu downgrade --file examples/telemetry_banded.quipu
quipu distill --file examples/telemetry_banded.quipu

# Start the zero-dependency Stdio JSON-RPC 2.0 MCP server
quipu mcp
```

---

## Visual CLI Cord Renderer (`quipu draw`)

You can render any `.quipu` document (`QUIPU/1.0` or `QUIPU/2.0`) as an ASCII/Unicode cord diagram in your terminal or inspect it programmatically in Python — displaying upward **Top Cords** (`▲`), the horizontal **Primary Cord** (`(LOOP)═══(TASSEL)`), **Pendant / Subsidiary** hierarchies (`↳`), **Alias pointers** (`⤴`), **band spacers** (`┄┄┄`), and **decimal knot clusters** (`●`, long-knot turns `≈NT≈`, figure-eight `⟨1E⟩`):

```bash
# CLI: render a .quipu fixture directly to stdout (or pass --json for {"ascii": ...})
quipu draw --file examples/telemetry_banded.quipu
quipu draw --file examples/ledger_sealed.quipu
```

```python
import quipu

with open("examples/telemetry_banded.quipu", encoding="utf-8") as fh:
    print(quipu.draw(fh.read(), max_rows=8))  # aliases: quipu.draw_quipu(), quipu.render_quipu_ascii()
```

### Example 1: Banded Telemetry, Anchors/Aliases, `~R`/`~V` Branches & `1E` Knot (`examples/telemetry_banded.quipu`)

```text
=== QUIPU/2.0: pipeline.telemetry.batch [mode=sealed tier=working tag="metrics" | knot=quipu-52623ab5e312] ===

  [TOP CORDS: UPWARD RECONCILIATIONS]
  ▲ [stage_metrics] ^count=4 | ^sum(tokens)=500 | ^sum(tokens, 0, 1)=300 | ^tol(tokens, pct=5.0)=490 | ^band(tokens, ratio="3/5")=500
  │
(LOOP)══════════════════════════════════════════════════════════════════════════(TASSEL)
[Head]                   PRIMARY CORD (HORIZONTAL TRUNK)                        [Tail]

  │── Pendant service [~R @W]: "edge-gateway"
  │── Pendant defaults [&prod_defaults ~Z @T0]: {2 items}
  │   ├── ↳ Subsidiary region: "eu-central-1"
  │   └── ↳ Subsidiary retries [^unit="attempts" ^wrap="bounded_backoff"]: val=41
  │       └── Knots: ●●●●(4D) -> ⟨1E⟩ [0M-0C-4D-1E]
  │── Pendant active_defaults: ⤴ *prod_defaults (alias)
  │── Pendant canary_override [~S ~V @T2 @D]: {1 items}
  │   └── ↳ Subsidiary retries [^nether=3]: val=38
  │       └── Knots: ●●●(3D) -> ≈8T≈(8U) [0M-0C-3D-8U]
  │── Pendant stage_metrics [@W ^unit="tokens"]: @table(stage:str, tokens:int, passed:bool) [4 rows]
  │   ├── [0] "ingest" | 120 | true
  │   ├── [1] "validate" | 180 | true
  │   ├── ┄┄┄ [--- band spacer] ┄┄┄
  │   ├── [2] "transform" | 140 | true
  │   └── [3] "export" | 60 | true
════════════════════════════════════════════════════════════════════════════════════════
```

### Example 2: Double-Entry Ledger with Upward Top-Cord Assertions (`examples/ledger_sealed.quipu`)

```text
=== QUIPU/2.0: treasury.q4.ledger [mode=sealed tier=working tag="fiscal_reconciliation" | knot=quipu-a351f60d7a7d] ===

  [TOP CORDS: UPWARD RECONCILIATIONS]
  ▲ [ledger] ^count=4 | ^sum(credit, 0, 1)=600 | ^net(credit, debt)=0 | ^equal_sum(credit, debt)=1000 | ^tol(credit, pct=5.0)=980 | ^band(credit, ratio="3/5")=1000 | ^quota(guard, pct=22.5)=4000
  │
(LOOP)══════════════════════════════════════════════════════════════════════════(TASSEL)
[Head]                   PRIMARY CORD (HORIZONTAL TRUNK)                        [Tail]

  │── Pendant currency [~Z @T0]: "USD"
  │── Pendant ledger [~Z @T0 @W ^unit="usd"]: @table(region:str, credit:int, debt:int, guard:int) [4 rows]
  │   ├── [0] "North" | 300 | 250 | 200
  │   ├── [1] "East" | 300 | 250 | 200
  │   ├── ┄┄┄ [--- band spacer] ┄┄┄
  │   ├── [2] "South" | 200 | 250 | 250
  │   └── [3] "West" | 200 | 250 | 250
════════════════════════════════════════════════════════════════════════════════════════
```

---

## MCP Client Configuration

`quipu` includes a pure-stdlib Stdio JSON-RPC 2.0 MCP server (`quipu mcp`) exposing the `quipu_codec` tool (`verify`, `encode`, `decode`, `from_json`, `to_json`, `micro`, `draw`, `benchmark`, `upgrade`, `downgrade`, `distill`).

Add the following to your MCP client configuration (Claude Desktop, Cursor, Windsurf, Kilo Code, etc.):

```json
{
  "mcpServers": {
    "quipu": {
      "command": "quipu",
      "args": ["mcp"]
    }
  }
}
```

---

## Andean Epigraphic Heritage

While all wire tokens and Python identifiers in `QUIPU/2.0` use concise English keywords, the data model is directly inspired by structural mechanisms documented in Andean *khipu* archives:

| Historical Term | Origin | Concise English Meaning | QUIPU Keyword / API |
| :--- | :--- | :--- | :--- |
| *khipu / quipu* | Quechua | Knotted-cord tactile accounting and archival record | `QUIPU/2.0`, `.quipu` |
| *kayte* | Quechua | Categorical label attached to the primary cord | `tag="..."` (`--tag`) |
| *canuto* | Spanish | Colored thread wrapping encoding source or codec provenance | `^wrap="..."` (`CordMeta.wrap`) |
| *inokatha / nakku* | Aymara / Quechua | Balanced double-entry check pairing credit and obligation cords | `^net(credit, debt)` |
| *yapa / qhincha* | Quechua | Permissible positive margin (*yapa*) vs overrun breach (*qhincha*) | `^tol(col, pct=N)` |
| *waranqa* | Quechua | Administrative unit of 1,000 capping working-record granularity | `MAX_WORKING_ROWS = 1000` |
| *yupana* | Quechua | Stepped counting board quantizing quantities into scale buckets | `SCALE_BUCKETS`, `quantize_bucket()` |
| *khipus enlazados* | Spanish | Companion khipus linked under one supervisory hub cord | `link_quipus(..., hub_id=...)` |
| *chakana* (spacer) | Quechua | Knotless spacing interval dividing banded cord groups | `---` spacer & `^band` |
| *hanan / hurin* (recto / verso) | Quechua | Dual paired structural attachment sides (primary vs shadow) | `~R` / `~V` (`CordAttachment`) |
| *Z / S spin* | Epigraphy | Directional fiber ply twist distinguishing canonical vs mutable cords | `~Z` / `~S` (`CordSpin`) |

---

## Conformance Profiles & Interoperability Vectors

`quipu` targets strict RFC-grade interoperability across four incremental conformance profiles defined in [docs/SPECIFICATION.md](docs/SPECIFICATION.md):

- **Profile A — Core Reader/Writer**: Lossless `QUIPU/1.0` & `QUIPU/2.0` parsing, JSON bijection (`loads`/`dumps`, `load`/`dump`), deterministic canonical serialization, and SHA-256 `=~` sealing.
- **Profile B — Full Static Verifier**: Deterministic 7-law (`1.0`) and 10-law (`2.0`) validation (`QLAW_01`..`QLAW_10`), plus explicit error routing between parse syntax failures (`QLAW_00_SYNTAX` -> `SYNTAX_ERROR`) and resource/safety bounds (`QLAW_07_SAFETY_BOUNDS` -> `SAFETY_VIOLATION`).
- **Profile C — Shims, Distillation & Federation**: Lossless `upgrade_quipu_to_v2()`, `downgrade_quipu_to_v1()`, `distill_working_to_summary()`, and multi-packet `link_quipus()`.
- **Profile D — Operational Renderers, CLI & Stdio MCP**: `render_quipu_micro()`, `draw()` (`MAX_ASCII_CHARS = 8_000`), all 11 CLI subcommands, and the Stdio JSON-RPC 2.0 MCP server (`2024-11-05`).

Appendix A of [docs/SPECIFICATION.md](docs/SPECIFICATION.md) ships **6 positive golden vectors (`V1`–`V6`)** with locked SHA-256 seals and **12 negative syntax/law vectors (`NEG-01`..`NEG-12`)**, verified automatically by [tests/test_spec_conformance.py](tests/test_spec_conformance.py).

---

## Documentation & Examples

- **Formal Specification**: [docs/SPECIFICATION.md](docs/SPECIFICATION.md) — RFC-grade wire specification covering Conformance Profiles A–D, conflict-free EBNF, byte-exact lexical escaping, canonical SHA-256 sealing, `auto_table` column inference, `QLAW_00`..`QLAW_10`, operational renderers (`MAX_ASCII_CHARS = 8_000`), CLI & MCP (`2024-11-05`) contracts, `application/quipu` media-type template, 18 normative interoperability test vectors, and heritage glossary.
- **Cookbook & Patterns**: [docs/EXAMPLES.md](docs/EXAMPLES.md) — End-to-end recipes for configs, double-entry ledgers, banded telemetry, decorators, compatibility shims, CLI, and MCP JSON-RPC.
- **Runnable `.quipu` Fixtures**:
  - [examples/config_lax.quipu](examples/config_lax.quipu) — Ergonomic headerless config with comments
  - [examples/ledger_sealed.quipu](examples/ledger_sealed.quipu) — Sealed `QUIPU/2.0` double-entry ledger (`^net`, `^equal_sum`, `^tol`, `^band`, `^quota`, `---`)
  - [examples/telemetry_banded.quipu](examples/telemetry_banded.quipu) — Sealed `QUIPU/2.0` banded telemetry with decorators & `&`/`*` alias
  - [examples/legacy_v1.quipu](examples/legacy_v1.quipu) — Sealed `QUIPU/1.0` packet for backward-compatibility testing

---

## License

MIT © [Serhii Kupriienko](https://github.com/skupriienko)
