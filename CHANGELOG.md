# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-25

### Added
- Initial standalone public release of `quipu` implementing the QUIPU/2.0 and QUIPU/1.0 (`.quipu`) data and provenance format with zero runtime dependencies.
- Lossless bidirectional JSON and Python object isomorphism (`loads`, `dumps`, `load`, `dump`, `json_to_quipu`, `quipu_to_json`).
- Typed columnar `@table(...)` encoding with Top-Cord arithmetic invariants (`^count`, `^sum`, slice `^sum`, `^tol`, `^net`, `^equal_sum`, `^band`, `^quota`, `^layout`) and row spacers (`---`).
- Provenance, mutability, branch attachment, and double-entry decorators (`~Z`/`~S`, `~R`/`~V`, `@T0..@T3`, `@W`/`@D`, `^unit`, `^wrap`, `^nether`, `&anchor`/`*alias`, `^knots`).
- Static verification engine (`verify`, `verify_quipu`) enforcing 7 laws for `QUIPU/1.0` and 10 laws for `QUIPU/2.0`, plus SHA-256 knot sealing (`=~ knot="quipu-..."`).
- Compatibility shims (`upgrade_quipu_to_v2`, `downgrade_quipu_to_v1`, `distill_working_to_summary`, `link_quipus`).
- Standalone `quipu` CLI and zero-dependency Stdio JSON-RPC 2.0 MCP server (`quipu mcp`, `QuipuMCPServer`, `serve_mcp_stdio`).
- PEP 517/621 packaging (`pyproject.toml`, `setup.py`, `MANIFEST.in`, `src/quipu/py.typed`), MIT License, Ruff/Mypy strict configs, and GitHub Actions CI matrix (Python 3.10–3.13).
