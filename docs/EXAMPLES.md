# QUIPU/2.0 & QUIPU/1.0 Examples Cookbook

Practical recipes covering every wire variation, primitive decorator, table invariant, compatibility shim, Python stream API, CLI command, and Stdio MCP JSON-RPC workflow.

Runnable `.quipu` fixtures referenced below live in [`examples/`](../examples/):
- [`examples/config_lax.quipu`](../examples/config_lax.quipu)
- [`examples/ledger_sealed.quipu`](../examples/ledger_sealed.quipu)
- [`examples/telemetry_banded.quipu`](../examples/telemetry_banded.quipu)
- [`examples/legacy_v1.quipu`](../examples/legacy_v1.quipu)

---

## 1. Ergonomic Headerless `lax` Configuration

**What & Why**: Headerless `.quipu` files default to `mode=lax`, allowing `#` comments, unquoted keys, and trailing commas while still decoding via `loads()` to standard Python/JSON dicts with zero parser hazards.

See [`examples/config_lax.quipu`](../examples/config_lax.quipu):

```text
# Ergonomic headerless QUIPU config (defaults to QUIPU/1.0 lax mode)
# Supports inline comments, unquoted bare keys, and trailing commas.

service: "edge-router"
environment: "production"
replicas: 3
tls_enabled: true

timeouts: {
  connect_ms: 250,
  read_ms: 1500,
  idle_ms: 30000,
}

allow_origins: [
  "https://app.example.org",
  "https://admin.example.org",
]
```

```python
import quipu

with open("examples/config_lax.quipu", encoding="utf-8") as fh:
    cfg = quipu.load(fh)

assert cfg["replicas"] == 3
assert quipu.verify(open("examples/config_lax.quipu", encoding="utf-8").read())["valid"] is True
```

---

## 2. Sealed Service Manifest (`QUIPU/2.0 mode=sealed`)

**What & Why**: `mode=sealed` enforces `QLAW_01_MERKLE_SEAL`. Any single-byte modification to keys, values, decorators, or headers invalidates the `=~` SHA-256 knot footer before downstream code trusts the payload.

```python
import quipu

manifest = {
    "service": "auth-proxy",
    "version": "2.4.0",
    "routes": [
        {"path": "/token", "rpm": 1200, "auth": True},
        {"path": "/health", "rpm": 6000, "auth": False},
    ],
}

sealed_wire = quipu.dumps(manifest, doc_id="auth.proxy.manifest", mode="sealed", version="2.0")
report = quipu.verify(sealed_wire)
assert report["valid"] is True
assert report["knot"].startswith("quipu-")
```

---

## 3. Typed `@table` with `---` Spacers & Slice Sums

**What & Why**:
- `@table(col:type, ...)` eliminates repeated JSON object keys and strictly enforces `bool != int` (`QLAW_03`).
- `---` spacers and `^layout="banded"` group rows into logical phases without wrapping rows in nested sub-arrays (`QLAW_09`).
- `^sum(col, start, end)=V` audits inclusive row ranges `[start, end]` against truncation (`QLAW_08`).

```python
import quipu

banded_wire = """
~= QUIPU/2.0 id="release.pipeline" mode=lax tier=working tag="ci_metrics"

stages: @table(stage:str, tokens:int, passed:bool) ^layout="banded" ^count=4 ^sum(tokens)=500 ^sum(tokens, 0, 1)=300 {
  "ingest" | 120 | true
  "validate" | 180 | true
  ---
  "transform" | 140 | true
  "export" | 60 | true
}
"""

rep = quipu.verify(banded_wire)
assert rep["valid"] is True

doc = quipu.parse(banded_wire)
tbl = doc.root.value["stages"].value
assert tbl.spacer_indices == [2]
assert tbl.layout == "banded"
assert quipu.loads(banded_wire)["stages"][0] == {"stage": "ingest", "tokens": 120, "passed": True}
```

---

## 4. Double-Entry Ledger (`^net`, `^equal_sum`, `@W`/`@D`)

**What & Why**:
- `@W` (`CordPolarity.WHITE`) marks credit/asset/budget cords; `@D` (`CordPolarity.DARK`) marks obligation/debt/charge cords.
- `^net(credit, debt)=N` enforces `sum(credit) - sum(debt) == N` statically (`QLAW_08`).
- `^equal_sum(left, right)=P` enforces `sum(left) == P` and `sum(right) == P`.

See [`examples/ledger_sealed.quipu`](../examples/ledger_sealed.quipu) for a full sealed example combining double-entry balance with tolerance, band ratio, and quota projection:

```text
~= QUIPU/2.0 id="treasury.q4.ledger" mode=sealed tier=working tag="fiscal_reconciliation"

currency ~Z @T0: "USD"
ledger ~Z @T0 @W ^unit="usd": @table(region:str, credit:int, debt:int, guard:int) ^layout="banded" ^count=4 ^sum(credit, 0, 1)=600 ^net(credit, debt)=0 ^equal_sum(credit, debt)=1000 ^tol(credit, pct=5.0)=980 ^band(credit, ratio="3/5")=1000 ^quota(guard, pct=22.5)=4000 {
  "North" | 300 | 250 | 200
  "East" | 300 | 250 | 200
  ---
  "South" | 200 | 250 | 250
  "West" | 200 | 250 | 250
}

=~ knot="quipu-a351f60d7a7d" sha256="a351f60d7a7d135169a6f00b4220dcaf5b8d7b87e8693ae3820f37ea65997854" reconciled=true
```

---

## 5. Tolerance (`^tol`), Band Ratio (`^band`) & Quota (`^quota`)

**What & Why**:
- `^tol(col, pct=T)=N`: guards against budget overruns or SLO creep by verifying `N <= sum(col) <= N * (1 + T/100)`. Exceeding it fails `QLAW_08` with `"Tolerance breach"`.
- `^band(col, ratio="R")=V`: verifies total `sum(col) == V` and pre-spacer ratio (`"1/2"`, `"1/3"`, `"2/3"`, `"2/5"`, `"3/5"`).
- `^quota(col, pct=P)=Pop`: projects total cohort capacity (`sum(col) / (P / 100) == Pop`).

```python
import quipu

# Failing tolerance breach example (> 5% overrun)
overrun = """
~= QUIPU/2.0 id="budget.overrun" mode=lax
{
  spend: @table(item:str, usd:int) ^tol(usd, pct=5.0)=1000 {
    "compute" | 1200
  }
}
"""
rep = quipu.verify(overrun)
assert rep["valid"] is False
assert rep["findings"][0]["law"] == "QLAW_08_BALANCE_BOUNDS"
assert "Tolerance breach" in rep["findings"][0]["message"]

# Programmatic inverse quota calculation
assert quipu.project_quota_population(900, quota_pct=22.5) == 4000.0
```

---

## 6. Bounded `&anchor` / `*alias` Reuse

**What & Why**: `&anchor` and `*alias` reuse shared subtrees without duplicating config blocks. Unlike YAML aliases, `QLAW_04` caps total expansions at `MAX_ALIAS_EXPANSIONS = 1_024` (`CWE-776` protection) and `QLAW_09` caps chained alias depth at `MAX_COMPOUND_SUM_DEPTH = 10`.

```python
import quipu

dry_cfg = """
~= QUIPU/2.0 id="dry.config" mode=lax

defaults &base_limits ~Z @T0: {
  timeout_ms ^unit="ms": 1500
  retries: 3
}
service_a: *base_limits
service_b: *base_limits
"""

data = quipu.loads(dry_cfg)
assert data["service_a"] == data["service_b"] == {"timeout_ms": 1500, "retries": 3}
```

---

## 7. Decorators: Mutability, Branch Side, Trust, Units, Wrappers & Knots

**What & Why**:
- `~Z` / `~S`: locks immutable SSOT configs (`~Z`) and rejects nested `~S` overrides (`QLAW_05`).
- `~R` / `~V`: pairs primary (`~R`) and shadow/canary (`~V`) values in one sealed file.
- `@T0..@T3`: isolates untrusted payloads (`@T2`/`@T3`) so `@T0`/`@T1` cords cannot alias them (`QLAW_06`).
- `^unit`, `^wrap`, `^nether`, `^knots` (`1E`): embed units, codec tags, auxiliary audit weights, and base-10 integer parity without altering `loads()` values.

See [`examples/telemetry_banded.quipu`](../examples/telemetry_banded.quipu):

```python
import quipu

with open("examples/telemetry_banded.quipu", encoding="utf-8") as fh:
    wire = fh.read()

assert quipu.verify(wire)["valid"] is True
decoded = quipu.loads(wire)
assert decoded["defaults"]["retries"] == 41
assert decoded["canary_override"]["retries"] == 38

# Base-10 knots with 1E figure-eight singular unit marker
assert quipu.encode_knots(41, figure_eight_unit=True) == "0M-0C-4D-1E"
assert quipu.decode_knots("0M-0C-4D-1E") == 41
```

---

## 8. Bit Registers, Scale Buckets & Micro Fingerprints

**What & Why**: `encode_7bit`, `encode_14bit`, `SCALE_BUCKETS`, `quantize_bucket`, and `render_quipu_micro` summarize cord posture and magnitude in $O(1)$ for telemetry routers and caches without full AST traversal.

```python
import quipu
from quipu import CordAttachment, CordMeta, CordPolarity, CordSpin, CordTier

meta = CordMeta(
    spin=CordSpin.Z,
    tier=CordTier.T0,
    attachment=CordAttachment.R,
    polarity=CordPolarity.WHITE,
    unit="tokens",
    anchor="base",
)
print(quipu.encode_7bit(meta.spin, meta.tier, has_numeric=True, is_table=False))
print(quipu.encode_14bit(meta, has_numeric=True, is_table=False))
print(quipu.quantize_bucket(12))   # -> 15 (from SCALE_BUCKETS)
print(quipu.quantize_bucket(1200)) # -> 1000 (clamped ceiling)

doc = quipu.parse(open("examples/telemetry_banded.quipu", encoding="utf-8").read())
print(quipu.render_quipu_micro(doc))
```

---

## 9. `QUIPU/1.0` <-> `QUIPU/2.0` Upgrade & Downgrade Shims

**What & Why**: `upgrade_quipu_to_v2()` promotes legacy `QUIPU/1.0` packets while preserving the source knot in `parent`; `downgrade_quipu_to_v1()` strips `2.0` extensions so legacy 7-law consumers read the exact same JSON data.

```python
import quipu

v1_wire = open("examples/legacy_v1.quipu", encoding="utf-8").read()
assert quipu.is_quipu_v1(v1_wire) is True

# Upgrade 1.0 -> 2.0 (records v1 seal knot in parent)
v2_doc = quipu.upgrade_quipu_to_v2(v1_wire, admin_tier="working", tag="release")
v2_wire = quipu.dump_quipu(v2_doc, recompute_seal=True)
assert quipu.is_quipu_v2(v2_wire) is True
assert v2_doc.parent == "quipu-355878d6a9b5"
assert quipu.loads(v2_wire) == quipu.loads(v1_wire)

# Downgrade 2.0 -> 1.0 cleanly
v1_again_doc = quipu.downgrade_quipu_to_v1(v2_wire)
v1_again_wire = quipu.dump_quipu(v1_again_doc, recompute_seal=True)
assert quipu.verify(v1_again_wire)["version"] == "QUIPU/1.0"
assert len(quipu.verify(v1_again_wire)["laws_checked"]) == 7
assert quipu.loads(v1_again_wire) == quipu.loads(v2_wire)
```

---

## 10. `working -> summary` Distillation & `link_quipus` Federation

**What & Why**:
- `distill_working_to_summary()` keeps `tier=working` tables under `MAX_WORKING_ROWS = 1000` by compacting tables into `tier=summary` rollups (`row_count`, `column_count`, `band_count`, `numeric_sums`) with `parent` pointing to the source knot.
- `link_quipus()` federates mixed `QUIPU/1.0` and `QUIPU/2.0` packets into one sealed `hub` manifest (`tag="linked_hub"`).

```python
import quipu

working_wire = open("examples/telemetry_banded.quipu", encoding="utf-8").read()
legacy_wire = open("examples/legacy_v1.quipu", encoding="utf-8").read()

summary_doc = quipu.distill_working_to_summary(working_wire)
assert summary_doc.admin_tier.value == "summary"
assert summary_doc.parent == "quipu-52623ab5e312"

hub_doc = quipu.link_quipus({"telemetry": summary_doc, "legacy": legacy_wire}, hub_id="HubA")
hub_wire = quipu.dump_quipu(hub_doc, recompute_seal=True)
assert quipu.verify(hub_wire)["valid"] is True
assert len(quipu.loads(hub_wire)["members"]) == 2
```

---

## 11. CLI & Stdio MCP JSON-RPC Usage

### CLI Recipes

```bash
# Verify every fixture in examples/
quipu verify --file examples/config_lax.quipu --json
quipu verify --file examples/ledger_sealed.quipu --json
quipu verify --file examples/telemetry_banded.quipu --json
quipu verify --file examples/legacy_v1.quipu --json

# Convert JSON -> QUIPU/2.0 -> JSON
quipu from-json --file payload.json --mode sealed --format-version 2.0 > payload.quipu
quipu to-json --file payload.quipu

# Benchmark and compact micro inspection
quipu bench --file examples/ledger_sealed.quipu --json
quipu micro --file examples/ledger_sealed.quipu
```

### Stdio MCP JSON-RPC 2.0 (`quipu mcp`)

When launched via `quipu mcp`, the server reads newline-delimited JSON-RPC 2.0 requests from `stdin` and writes responses to `stdout`:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"quipu_codec","arguments":{"action":"from_json","json_text":"{\"service\":\"edge\",\"items\":[{\"id\":1,\"n\":10},{\"id\":2,\"n\":20}]}","mode":"sealed","version":"2.0"}}}
```
