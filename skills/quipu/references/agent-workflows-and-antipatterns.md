# QUIPU Agent Workflows & Anti-Patterns

All valid `.quipu` examples below use real verified SHA-256 knots checked by `tests/test_agent_skill.py`.

---

## Pattern 1 — Happy Path: Config -> Sealed `@table` Receipt + Terminal Diagram

Use when an agent emits structured build or benchmark telemetry that downstream hooks or humans verify:

```quipu
~= QUIPU/2.0 id="agent.ci.telemetry" mode=sealed tier=working tag="build_receipt"

service ~R @W: "edge-gateway"
retries ~Z @T0 ^unit="attempts" ^knots="0M-0C-0D-3U": 3
stages @W ^unit="ms": @table(step:str, duration_ms:int, ok:bool) ^layout="banded" ^count=3 ^sum(duration_ms)=185 ^tol(duration_ms, pct=10.0)=175 {
  "lint" | 35 | true
  "typecheck" | 60 | true
  ---
  "tests" | 90 | true
}

=~ knot="quipu-9372287e8464" sha256="9372287e846459866d32c9e5c311f32458c6a1078186cfb977ebda57ee19b920" reconciled=true
```

Run verification, terminal cord diagram, and single-line micro fingerprint:

```bash
quipu verify --file telemetry.quipu --json
quipu draw --file telemetry.quipu --max-rows 8
quipu micro --file telemetry.quipu
```

---

## Pattern 2 — Secure Multi-Agent Variant: Taint Quarantine, Double-Entry Check & Federation

Keep verified `T0` policy anchors strictly separate from untrusted `T3` webhook/RAG inputs, enforce double-entry conservation (`^net=0`, `^band`), and distill or link multiple agent outputs:

```quipu
~= QUIPU/2.0 id="treasury.batch" mode=sealed tier=working tag="finops_audit" parent="none"

policy &budget_guard ~Z @T0: {
  currency: "USD"
  max_slippage_pct: 5.0
}
worker_policy @T1: *budget_guard
external_quote ~S @T3 ^wrap="raw_webhook": {
  vendor: "partner-feed"
  raw_note: "unverified quote"
}
ledger ~Z @T0 @W ^unit="usd": @table(desk:str, credit:int, debt:int) ^layout="banded" ^count=4 ^net(credit, debt)=0 ^equal_sum(credit, debt)=1000 ^band(credit, ratio="3/5")=1000 {
  "Compute" | 300 | 250
  "Storage" | 300 | 250
  ---
  "Network" | 200 | 250
  "Reserve" | 200 | 250
}

=~ knot="quipu-57608e95642b" sha256="57608e95642b06b821c5c7a3a293b83724ef2f73add8b4918e6be4b6f57a912a" reconciled=true
```

Python workflow for verification, summary compaction, and multi-packet federation:

```python
import quipu

report = quipu.verify(ledger_wire)
assert report["valid"] is True and len(report["laws_checked"]) == 10

summary_doc = quipu.distill_working_to_summary(ledger_wire)
assert summary_doc.parent == report["knot"]

hub_doc = quipu.link_quipus({"ledger": summary_doc, "config": quipu.sample_quipu_v1()}, hub_id="HubMain")
hub_wire = quipu.dump_quipu(hub_doc, recompute_seal=True)
assert quipu.verify(hub_wire)["valid"] is True
```

---

## Anti-Patterns & Corrected Fixes

### Anti-Pattern 1 — Unquoted String Values & Hand-Invented Seal

```quipu
# ANTI-PATTERN: bare string raises QLAW_00_SYNTAX; fake seal fails QLAW_01_MERKLE_SEAL
~= QUIPU/2.0 id="bad.seal" mode=sealed

env: production
=~ knot="quipu-000000000000" sha256="0000000000000000000000000000000000000000000000000000000000000000" reconciled=true
```

**Fix**: Always quote strings and generate the seal programmatically via `quipu.dumps({"env": "production"}, doc_id="good.seal")` or `quipu from-json`.

### Anti-Pattern 2 — Mutable `~S` Inside Explicit `~Z` & `bool` in `int` Column

```quipu
# ANTI-PATTERN: triggers QLAW_05_SPIN_CONTAINMENT and QLAW_03_COLUMN_TYPES
~= QUIPU/2.0 id="bad.types" mode=lax

defaults ~Z: {
  override ~S: 10
}
checks: @table(ok:int) {
  true
}
```

**Fix**: Keep mutable overrides (`~S`) in a sibling branch (`~V`) outside explicit `~Z`, and declare boolean columns explicitly as `ok:bool`.

### Anti-Pattern 3 — Trust Escalation (`@T0` Aliasing `@T3`)

```quipu
# ANTI-PATTERN: triggers QLAW_06_TAINT_NON_ESCALATION
~= QUIPU/2.0 id="bad.taint" mode=lax

untrusted &ext_input @T3: "SELECT * FROM users"
trusted_query @T0: *ext_input
```

**Fix**: Never alias `T2`/`T3` anchors from `T0`/`T1` cords; sanitize/validate external payloads explicitly before constructing clean `T0`/`T1` values.
