"""quipu.codec — Tokenizer, Recursive-Descent Parser, Isomorphic Codec & Seal Engine.

Implements both QUIPU/2.0 (default) and lossless QUIPU/1.0 (.quipu) compatibility:
- Lossless JSON / Python value isomorphism (loads/dumps, load/dump, loads_quipu/dumps_quipu)
- Comments (# ...), row spacers (---), and trailing-comma tolerance
- Columnar typed @table(...) with v1 (^count, ^sum) and v2 directives
- Inline spin (~Z/~S), branch side (~R/~V), tier (@T0..@T3), polarity (@W/@D), anchors & knots
- Deterministic canonical serialization and SHA-256 knot footer (=~)
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import IO, Any

from .ast_nodes import (
    DEFAULT_QUIPU_VERSION,
    MAX_ALIAS_EXPANSIONS,
    MAX_QUIPU_BYTES,
    MAX_QUIPU_DEPTH,
    QUIPU_V1,
    QUIPU_V2,
    SUPPORTED_QUIPU_VERSIONS,
    VALID_COLUMN_TYPES,
    AdminTier,
    CordAlias,
    CordAttachment,
    CordMeta,
    CordPolarity,
    CordSpin,
    CordTier,
    QuipuDocument,
    QuipuMode,
    QuipuNode,
    QuipuSeal,
    QuipuSyntaxError,
    QuipuTable,
    TopCordSpec,
    encode_incan_knots,
    encode_urton_7bit,
    encode_urton_14bit,
    is_valid_scalar_for_table,
    normalize_quipu_version,
)

_IDENT_START_RE = re.compile(r"[A-Za-z_]")
_IDENT_CHAR_RE = re.compile(r"[A-Za-z0-9_.\-]")
_BARE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_NUMBER_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_RESERVED_BARE = frozenset({"true", "false", "null", "_"})

_SINGLE_CHAR_TOKENS: dict[str, str] = {
    "{": "LBRACE",
    "}": "RBRACE",
    "[": "LBRACK",
    "]": "RBRACK",
    "(": "LPAREN",
    ")": "RPAREN",
    ":": "COLON",
    ",": "COMMA",
    "|": "PIPE",
    "=": "EQ",
    "@": "AT",
    "~": "TILDE",
    "&": "AMP",
    "*": "STAR",
    "^": "CARET",
    "/": "SLASH",
    "?": "QMARK",
}

_DECORATOR_FLAGS = (
    "spin",
    "tier",
    "anchor",
    "knots",
    "attachment",
    "polarity",
    "unit",
    "wrap",
    "nether",
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    line: int
    col: int


class _Lexer:
    """Single-pass lexical scanner for QUIPU/1.0 and QUIPU/2.0 wire text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.i = 0
        self.line = 1
        self.col = 1
        self.tokens: list[_Token] = []

    def _adv(self, count: int = 1) -> None:
        for _ in range(count):
            if self.text[self.i] == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            self.i += 1

    def _decode_string(self, raw_slice: str, tok_line: int, tok_col: int) -> str:
        try:
            parsed = json.loads(raw_slice)
        except json.JSONDecodeError as exc:
            raise QuipuSyntaxError(f"Invalid string literal: {exc}", tok_line, tok_col) from exc
        if not isinstance(parsed, str):
            raise QuipuSyntaxError("Expected JSON string literal", tok_line, tok_col)
        return parsed

    def _scan_string(self, tok_line: int, tok_col: int) -> None:
        start = self.i
        self._adv()
        esc = False
        while self.i < self.n:
            c = self.text[self.i]
            if c in ("\n", "\r"):
                raise QuipuSyntaxError(
                    "Unterminated string literal before newline", tok_line, tok_col
                )
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                self._adv()
                val = self._decode_string(self.text[start : self.i], tok_line, tok_col)
                self.tokens.append(_Token("STRING", val, tok_line, tok_col))
                return
            self._adv()
        raise QuipuSyntaxError("Unterminated string literal", tok_line, tok_col)

    def _scan_number(self, tok_line: int, tok_col: int) -> None:
        m = _NUMBER_RE.match(self.text, self.i)
        if not m:
            snippet = self.text[self.i : self.i + 8]
            raise QuipuSyntaxError(f"Malformed number starting at {snippet!r}", tok_line, tok_col)
        num_raw = m.group(0)
        after = self.i + len(num_raw)
        if after < self.n and (self.text[after].isalnum() or self.text[after] == "_"):
            bad = self.text[self.i : after + 2]
            raise QuipuSyntaxError(f"Invalid numeric token {bad!r}", tok_line, tok_col)
        self.tokens.append(_Token("NUMBER", num_raw, tok_line, tok_col))
        self._adv(len(num_raw))

    def _scan_spacer_or_number(self, tok_line: int, tok_col: int) -> None:
        if self.text.startswith("---", self.i):
            after = self.i + 3
            if after >= self.n or self.text[after] in (" ", "\t", "\r", "\n", "#"):
                self.tokens.append(_Token("SPACER", "---", tok_line, tok_col))
                self._adv(3)
                return
        self._scan_number(tok_line, tok_col)

    def _scan_ident_or_error(self, ch: str, tok_line: int, tok_col: int) -> None:
        if not _IDENT_START_RE.match(ch):
            raise QuipuSyntaxError(f"Unexpected character {ch!r}", tok_line, tok_col)
        start = self.i
        while self.i < self.n and _IDENT_CHAR_RE.match(self.text[self.i]):
            self._adv()
        self.tokens.append(_Token("IDENT", self.text[start : self.i], tok_line, tok_col))

    def _scan_token_body(self, ch: str, tok_line: int, tok_col: int) -> None:
        if self.text.startswith("~=", self.i):
            self.tokens.append(_Token("HEADER_OP", "~=", tok_line, tok_col))
            self._adv(2)
        elif self.text.startswith("=~", self.i):
            self.tokens.append(_Token("SEAL_OP", "=~", tok_line, tok_col))
            self._adv(2)
        elif ch in _SINGLE_CHAR_TOKENS:
            self.tokens.append(_Token(_SINGLE_CHAR_TOKENS[ch], ch, tok_line, tok_col))
            self._adv()
        elif ch == '"':
            self._scan_string(tok_line, tok_col)
        elif ch == "-" or ch.isdigit():
            self._scan_spacer_or_number(tok_line, tok_col)
        else:
            self._scan_ident_or_error(ch, tok_line, tok_col)

    def tokenize(self) -> list[_Token]:
        while self.i < self.n:
            ch = self.text[self.i]
            if ch in (" ", "\t", "\r"):
                self._adv()
                continue
            if ch == "\n":
                self.tokens.append(_Token("NEWLINE", "\n", self.line, self.col))
                self._adv()
                continue
            if ch == "#":
                while self.i < self.n and self.text[self.i] != "\n":
                    self._adv()
                continue
            self._scan_token_body(ch, self.line, self.col)
        self.tokens.append(_Token("EOF", "", self.line, self.col))
        return self.tokens


def _tokenize(text: str) -> list[_Token]:
    return _Lexer(text).tokenize()


def _parse_number_token(tok: _Token) -> int | float:
    raw = tok.value
    if "." in raw or "e" in raw or "E" in raw:
        try:
            fval = float(raw)
        except ValueError as exc:
            raise QuipuSyntaxError(f"Invalid float {raw!r}", tok.line, tok.col) from exc
        if not math.isfinite(fval):
            raise QuipuSyntaxError(f"Non-finite float {raw!r} rejected", tok.line, tok.col)
        return fval
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise QuipuSyntaxError(f"Invalid integer {raw!r}", tok.line, tok.col) from exc


def _node_uses_v2(node: QuipuNode) -> bool:
    if node.meta.has_v2_annotations():
        return True
    val = node.value
    if isinstance(val, QuipuTable):
        return val.has_v2_features()
    if isinstance(val, list):
        return any(_node_uses_v2(child) for child in val)
    if isinstance(val, dict):
        return any(_node_uses_v2(child) for child in val.values())
    return False


def _validate_v2_header_attrs(
    ver_str: str, kv: dict[str, str], hdr_tok: _Token
) -> AdminTier | None:
    for v2_attr in ("tier", "tag", "parent", "hub"):
        if v2_attr in kv and ver_str == QUIPU_V1:
            raise QuipuSyntaxError(
                f"Header '{v2_attr}=...' requires QUIPU/2.0", hdr_tok.line, hdr_tok.col
            )
    if "tier" not in kv:
        return None
    try:
        return AdminTier(str(kv["tier"]))
    except ValueError as exc:
        raise QuipuSyntaxError(
            f"Invalid QUIPU/2.0 tier {kv['tier']!r}", hdr_tok.line, hdr_tok.col
        ) from exc


def _select_meta_val(
    flag: str, key_seen: dict[str, bool], key_meta: CordMeta, val_meta: CordMeta
) -> Any:
    return getattr(key_meta, flag) if key_seen[flag] else getattr(val_meta, flag)


def _resolve_ident_literal(tok: _Token, context: str) -> Any:
    literals: dict[str, Any] = {"_": None, "null": None, "true": True, "false": False}
    if tok.value in literals:
        return literals[tok.value]
    if context == "table":
        raise QuipuSyntaxError(f"Invalid @table cell {tok.value!r}", tok.line, tok.col)
    raise QuipuSyntaxError(
        f"Unexpected bare identifier {tok.value!r} as value (quote strings)", tok.line, tok.col
    )


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.strict_v1 = False

    def _cur(self) -> _Token:
        return self.tokens[self.pos]

    def _skip_newlines(self) -> None:
        while self.pos < len(self.tokens) and self.tokens[self.pos].kind == "NEWLINE":
            self.pos += 1

    def _peek(self, *, skip_newlines: bool = True) -> _Token:
        idx = self.pos
        while skip_newlines and idx < len(self.tokens) and self.tokens[idx].kind == "NEWLINE":
            idx += 1
        return self.tokens[idx]

    def _consume(self, expected_kind: str | None = None, *, skip_newlines: bool = True) -> _Token:
        if skip_newlines:
            self._skip_newlines()
        tok = self.tokens[self.pos]
        if expected_kind is not None and tok.kind != expected_kind:
            raise QuipuSyntaxError(
                f"Expected {expected_kind}, got {tok.kind} ({tok.value!r})", tok.line, tok.col
            )
        self.pos += 1
        return tok

    def _require_v2(self, feature: str, tok: _Token) -> None:
        if self.strict_v1:
            raise QuipuSyntaxError(f"{feature} is only supported in {QUIPU_V2}", tok.line, tok.col)

    def parse_document(self) -> QuipuDocument:
        self._skip_newlines()
        if self._cur().kind == "EOF":
            raise QuipuSyntaxError("Empty QUIPU document", self._cur().line, self._cur().col)

        hdr: dict[str, Any] = {
            "has_header": False,
            "doc_id": "root",
            "mode": QuipuMode.LAX,
            "version": QUIPU_V1,
            "admin_tier": None,
            "tag": None,
            "parent": None,
            "hub": None,
        }
        if self._cur().kind == "HEADER_OP":
            hdr = self._parse_header()
            self.strict_v1 = hdr["version"] == QUIPU_V1

        self._skip_newlines()
        if self._cur().kind in ("EOF", "SEAL_OP"):
            raise QuipuSyntaxError(
                "QUIPU document contains no payload root", self._cur().line, self._cur().col
            )

        if self._looks_like_implicit_root_map():
            root_node = self._parse_implicit_root_map()
        else:
            root_node = self._parse_node(0)
        self._skip_newlines()
        seal = self._parse_seal() if self._cur().kind == "SEAL_OP" else None
        self._skip_newlines()
        if self._cur().kind != "EOF":
            tok = self._cur()
            raise QuipuSyntaxError(
                f"Unexpected trailing token {tok.kind} ({tok.value!r})", tok.line, tok.col
            )

        ver = (
            hdr["version"]
            if hdr["has_header"]
            else (QUIPU_V2 if _node_uses_v2(root_node) else QUIPU_V1)
        )
        return QuipuDocument(
            doc_id=hdr["doc_id"],
            mode=hdr["mode"],
            version=ver,
            root=root_node,
            seal=seal,
            admin_tier=hdr["admin_tier"],
            tag=hdr["tag"],
            parent=hdr["parent"],
            hub=hdr["hub"],
        )

    def _parse_header_kv(self) -> dict[str, str]:
        kv: dict[str, str] = {}
        while self._cur().kind not in ("NEWLINE", "EOF"):
            key_tok = self._consume("IDENT", skip_newlines=False)
            self._consume("EQ", skip_newlines=False)
            val_tok = self._consume(skip_newlines=False)
            if val_tok.kind not in ("STRING", "IDENT", "NUMBER"):
                raise QuipuSyntaxError(
                    f"Invalid header value for {key_tok.value!r}", val_tok.line, val_tok.col
                )
            kv[key_tok.value] = val_tok.value
        return kv

    def _parse_header(self) -> dict[str, Any]:
        hdr_tok = self._consume("HEADER_OP")
        ident = self._consume("IDENT", skip_newlines=False)
        self._consume("SLASH", skip_newlines=False)
        ver_tok = self._consume("NUMBER", skip_newlines=False)
        ver_str = f"{ident.value}/{ver_tok.value}"
        if ver_str not in SUPPORTED_QUIPU_VERSIONS:
            raise QuipuSyntaxError(
                f"Unsupported QUIPU version {ver_str!r}", hdr_tok.line, hdr_tok.col
            )

        kv = self._parse_header_kv()
        doc_id = str(kv.get("id", "root"))
        if not doc_id:
            raise QuipuSyntaxError('Header id="..." cannot be empty', hdr_tok.line, hdr_tok.col)
        try:
            mode = QuipuMode(str(kv.get("mode", "sealed")))
        except ValueError as exc:
            raise QuipuSyntaxError(
                f"Invalid QUIPU mode {kv.get('mode')!r}", hdr_tok.line, hdr_tok.col
            ) from exc

        admin_tier = _validate_v2_header_attrs(ver_str, kv, hdr_tok)

        return {
            "has_header": True,
            "version": ver_str,
            "doc_id": doc_id,
            "mode": mode,
            "admin_tier": admin_tier,
            "tag": kv.get("tag"),
            "parent": kv.get("parent"),
            "hub": kv.get("hub"),
        }

    def _parse_seal(self) -> QuipuSeal:
        seal_tok = self._consume("SEAL_OP")
        kv: dict[str, str] = {}
        while self._cur().kind not in ("NEWLINE", "EOF"):
            key_tok = self._consume("IDENT", skip_newlines=False)
            self._consume("EQ", skip_newlines=False)
            val_tok = self._consume(skip_newlines=False)
            if val_tok.kind not in ("STRING", "IDENT"):
                raise QuipuSyntaxError(
                    f"Invalid seal attribute {key_tok.value!r}", val_tok.line, val_tok.col
                )
            kv[key_tok.value] = val_tok.value
        if "knot" not in kv or "sha256" not in kv:
            raise QuipuSyntaxError(
                'Seal footer \'=~\' requires knot="..." and sha256="..."',
                seal_tok.line,
                seal_tok.col,
            )
        rec_raw = kv.get("reconciled", "true")
        if rec_raw not in ("true", "false"):
            raise QuipuSyntaxError(
                f"Invalid reconciled value {rec_raw!r}", seal_tok.line, seal_tok.col
            )
        return QuipuSeal(knot=kv["knot"], sha256=kv["sha256"], reconciled=(rec_raw == "true"))

    def _consume_tilde(self, state: dict[str, Any], seen: dict[str, bool]) -> None:
        self._consume("TILDE", skip_newlines=False)
        tok = self._consume("IDENT", skip_newlines=False)
        if tok.value in ("Z", "S"):
            if seen["spin"]:
                raise QuipuSyntaxError("Duplicate ~Z/~S spin decorator", tok.line, tok.col)
            state["spin"] = CordSpin(tok.value)
            seen["spin"] = True
        elif tok.value in ("R", "V"):
            self._require_v2(f"Attachment side ~{tok.value}", tok)
            if seen["attachment"]:
                raise QuipuSyntaxError("Duplicate ~R/~V attachment decorator", tok.line, tok.col)
            state["attachment"] = CordAttachment(tok.value)
            seen["attachment"] = True
        else:
            raise QuipuSyntaxError(
                f"Invalid ~{tok.value}; expected ~Z/~S or ~R/~V", tok.line, tok.col
            )

    def _consume_at_flag(
        self,
        flag: str,
        enum_val: CordTier | CordPolarity,
        err_msg: str,
        state: dict[str, Any],
        seen: dict[str, bool],
    ) -> bool:
        cur = self._cur()
        if seen[flag]:
            raise QuipuSyntaxError(err_msg, cur.line, cur.col)
        self._consume("AT", skip_newlines=False)
        self._consume("IDENT", skip_newlines=False)
        state[flag] = enum_val
        seen[flag] = True
        return True

    def _consume_at_or_stop(self, state: dict[str, Any], seen: dict[str, bool]) -> bool:
        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].kind == "IDENT":
            tag = self.tokens[self.pos + 1].value
            if tag == "table":
                return False
            if tag in ("T0", "T1", "T2", "T3"):
                return self._consume_at_flag(
                    "tier", CordTier(tag), "Duplicate @T0..@T3 decorator", state, seen
                )
            if tag in ("W", "D"):
                cur = self._cur()
                self._require_v2(f"Accounting polarity @{tag}", cur)
                return self._consume_at_flag(
                    "polarity", CordPolarity(tag), "Duplicate @W/@D polarity decorator", state, seen
                )
        cur = self._cur()
        raise QuipuSyntaxError("Expected @table, @T0..@T3, or @W/@D", cur.line, cur.col)

    def _consume_caret(self, state: dict[str, Any], seen: dict[str, bool]) -> None:
        self._consume("CARET", skip_newlines=False)
        tok = self._consume("IDENT", skip_newlines=False)
        name = tok.value
        if name in ("knots", "unit", "wrap"):
            if name in ("unit", "wrap"):
                self._require_v2(f"Cord decorator ^{name}", tok)
            if seen[name]:
                raise QuipuSyntaxError(f"Duplicate ^{name} decorator", tok.line, tok.col)
            self._consume("EQ", skip_newlines=False)
            state[name] = self._consume("STRING", skip_newlines=False).value
            seen[name] = True
            return
        if name == "nether":
            self._require_v2("Nether-knot decorator ^nether", tok)
            if seen["nether"]:
                raise QuipuSyntaxError("Duplicate ^nether decorator", tok.line, tok.col)
            self._consume("EQ", skip_newlines=False)
            state["nether"] = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            seen["nether"] = True
            return
        raise QuipuSyntaxError(f"Unknown node decorator ^{name}", tok.line, tok.col)

    def _parse_decorators(self) -> tuple[CordMeta, dict[str, bool]]:
        state: dict[str, Any] = {
            "spin": CordSpin.Z,
            "tier": CordTier.T0,
            "anchor": None,
            "knots": None,
            "attachment": None,
            "polarity": None,
            "unit": None,
            "wrap": None,
            "nether": None,
        }
        seen: dict[str, bool] = dict.fromkeys(_DECORATOR_FLAGS, False)
        while True:
            cur = self._cur()
            if cur.kind == "AMP":
                if seen["anchor"]:
                    raise QuipuSyntaxError("Duplicate &anchor decorator", cur.line, cur.col)
                self._consume("AMP", skip_newlines=False)
                state["anchor"] = self._consume("IDENT", skip_newlines=False).value
                seen["anchor"] = True
            elif cur.kind == "TILDE":
                self._consume_tilde(state, seen)
            elif cur.kind == "AT":
                if not self._consume_at_or_stop(state, seen):
                    break
            elif cur.kind == "CARET":
                self._consume_caret(state, seen)
            else:
                break
        return (
            CordMeta(
                spin=state["spin"],
                tier=state["tier"],
                anchor=state["anchor"],
                knots=state["knots"],
                explicit_spin=seen["spin"],
                explicit_tier=seen["tier"],
                attachment=state["attachment"],
                polarity=state["polarity"],
                unit=state["unit"],
                wrap=state["wrap"],
                nether=state["nether"],
            ),
            seen,
        )

    @staticmethod
    def _merge_meta(
        key_meta: CordMeta,
        key_seen: dict[str, bool],
        val_meta: CordMeta,
        val_seen: dict[str, bool],
        line: int,
        col: int,
    ) -> CordMeta:
        for flag in _DECORATOR_FLAGS:
            if key_seen[flag] and val_seen[flag]:
                raise QuipuSyntaxError(f"Conflicting duplicate {flag} decorator", line, col)
        return CordMeta(
            spin=_select_meta_val("spin", key_seen, key_meta, val_meta),
            tier=_select_meta_val("tier", key_seen, key_meta, val_meta),
            anchor=_select_meta_val("anchor", key_seen, key_meta, val_meta),
            knots=_select_meta_val("knots", key_seen, key_meta, val_meta),
            explicit_spin=key_seen["spin"] or val_seen["spin"],
            explicit_tier=key_seen["tier"] or val_seen["tier"],
            attachment=_select_meta_val("attachment", key_seen, key_meta, val_meta),
            polarity=_select_meta_val("polarity", key_seen, key_meta, val_meta),
            unit=_select_meta_val("unit", key_seen, key_meta, val_meta),
            wrap=_select_meta_val("wrap", key_seen, key_meta, val_meta),
            nether=_select_meta_val("nether", key_seen, key_meta, val_meta),
        )

    def _looks_like_implicit_root_map(self) -> bool:
        saved = self.pos
        saved_strict = self.strict_v1
        try:
            self._skip_newlines()
            first = self._cur()
            if first.kind == "STRING" or (
                first.kind == "IDENT" and first.value not in _RESERVED_BARE
            ):
                self.pos += 1
            else:
                return False
            self._parse_decorators()
            return self._peek(skip_newlines=False).kind == "COLON"
        except QuipuSyntaxError:
            return False
        finally:
            self.pos = saved
            self.strict_v1 = saved_strict

    def _parse_implicit_root_map(self) -> QuipuNode:
        entries: dict[str, QuipuNode] = {}
        while True:
            self._skip_newlines()
            cur = self._cur()
            if cur.kind in ("EOF", "SEAL_OP"):
                break
            key, node = self._parse_map_entry(depth=0)
            if key in entries:
                raise QuipuSyntaxError(f"Duplicate key {key!r} at root map", cur.line, cur.col)
            entries[key] = node
            nxt = self._cur()
            if nxt.kind == "COMMA":
                self._consume("COMMA", skip_newlines=False)
            elif nxt.kind not in ("NEWLINE", "EOF", "SEAL_OP"):
                raise QuipuSyntaxError(
                    f"Expected newline or ',' between root entries, got {nxt.kind} ({nxt.value!r})",
                    nxt.line,
                    nxt.col,
                )
        return QuipuNode(value=entries, meta=CordMeta())

    def _parse_map_entry(self, depth: int) -> tuple[str, QuipuNode]:
        key_tok = self._consume()
        if key_tok.kind == "STRING" or (
            key_tok.kind == "IDENT" and key_tok.value not in _RESERVED_BARE
        ):
            key = key_tok.value
        else:
            raise QuipuSyntaxError(f"Invalid map key {key_tok.value!r}", key_tok.line, key_tok.col)
        key_meta, key_seen = self._parse_decorators()
        self._consume("COLON", skip_newlines=False)
        val_start = self._peek(skip_newlines=True)
        node = self._parse_node(depth=depth + 1)
        val_seen = {
            "spin": node.meta.explicit_spin,
            "tier": node.meta.explicit_tier,
            "anchor": node.meta.anchor is not None,
            "knots": node.meta.knots is not None,
            "attachment": node.meta.attachment is not None,
            "polarity": node.meta.polarity is not None,
            "unit": node.meta.unit is not None,
            "wrap": node.meta.wrap is not None,
            "nether": node.meta.nether is not None,
        }
        merged = self._merge_meta(
            key_meta, key_seen, node.meta, val_seen, val_start.line, val_start.col
        )
        return key, QuipuNode(value=node.value, meta=merged)

    def _parse_node(self, depth: int) -> QuipuNode:
        if depth > MAX_QUIPU_DEPTH:
            tok = self._peek()
            raise QuipuSyntaxError(
                f"Maximum nesting depth ({MAX_QUIPU_DEPTH}) exceeded", tok.line, tok.col
            )
        self._skip_newlines()
        meta, _seen = self._parse_decorators()
        self._skip_newlines()
        cur = self._cur()
        val = self._parse_node_value(cur, depth)
        return QuipuNode(value=val, meta=meta)

    def _parse_node_value(self, cur: _Token, depth: int) -> Any:
        if cur.kind == "LBRACE":
            return self._parse_braced_map(depth)
        if cur.kind == "LBRACK":
            return self._parse_list(depth)
        if cur.kind == "AT":
            return self._parse_table(depth)
        if cur.kind == "STAR":
            self._consume("STAR", skip_newlines=False)
            return CordAlias(target=self._consume("IDENT", skip_newlines=False).value)
        if cur.kind == "STRING":
            return self._consume("STRING", skip_newlines=False).value
        if cur.kind == "NUMBER":
            return _parse_number_token(self._consume("NUMBER", skip_newlines=False))
        if cur.kind == "IDENT":
            return _resolve_ident_literal(self._consume("IDENT", skip_newlines=False), "value")
        raise QuipuSyntaxError(
            f"Expected value token, got {cur.kind} ({cur.value!r})", cur.line, cur.col
        )

    def _parse_braced_map(self, depth: int) -> dict[str, QuipuNode]:
        self._consume("LBRACE")
        entries: dict[str, QuipuNode] = {}
        while True:
            self._skip_newlines()
            cur = self._cur()
            if cur.kind == "RBRACE":
                self._consume("RBRACE", skip_newlines=False)
                return entries
            key, node = self._parse_map_entry(depth)
            if key in entries:
                raise QuipuSyntaxError(f"Duplicate key {key!r} in map", cur.line, cur.col)
            entries[key] = node
            nxt = self._cur()
            if nxt.kind == "COMMA":
                self._consume("COMMA", skip_newlines=False)
            elif nxt.kind not in ("NEWLINE", "RBRACE"):
                raise QuipuSyntaxError(
                    f"Expected ',', newline, or '}}' in map, got {nxt.kind}", nxt.line, nxt.col
                )

    def _parse_list(self, depth: int) -> list[QuipuNode]:
        self._consume("LBRACK")
        items: list[QuipuNode] = []
        while True:
            self._skip_newlines()
            if self._cur().kind == "RBRACK":
                self._consume("RBRACK", skip_newlines=False)
                return items
            items.append(self._parse_node(depth=depth + 1))
            nxt = self._cur()
            if nxt.kind == "COMMA":
                self._consume("COMMA", skip_newlines=False)
            elif nxt.kind not in ("NEWLINE", "RBRACK"):
                raise QuipuSyntaxError(
                    f"Expected ',', newline, or ']' in list, got {nxt.kind}", nxt.line, nxt.col
                )

    def _parse_single_column(self, seen_cols: set[str]) -> tuple[str, str]:
        col_tok = self._consume("IDENT", skip_newlines=False)
        self._consume("COLON", skip_newlines=False)
        type_tok = self._consume("IDENT", skip_newlines=False)
        ctype = type_tok.value
        if self._cur().kind == "QMARK":
            self._consume("QMARK", skip_newlines=False)
            ctype = f"{ctype}?"
        if ctype not in VALID_COLUMN_TYPES:
            raise QuipuSyntaxError(
                f"Unsupported @table column type {ctype!r}", type_tok.line, type_tok.col
            )
        if col_tok.value in seen_cols:
            raise QuipuSyntaxError(
                f"Duplicate @table column {col_tok.value!r}", col_tok.line, col_tok.col
            )
        seen_cols.add(col_tok.value)
        return col_tok.value, ctype

    def _parse_table_columns(self, at_tok: _Token) -> list[tuple[str, str]]:
        self._consume("LPAREN", skip_newlines=False)
        columns: list[tuple[str, str]] = []
        seen_cols: set[str] = set()
        while True:
            self._skip_newlines()
            if self._cur().kind == "RPAREN":
                self._consume("RPAREN", skip_newlines=False)
                break
            columns.append(self._parse_single_column(seen_cols))
            if self._cur().kind == "COMMA":
                self._consume("COMMA", skip_newlines=False)
            elif self._peek(skip_newlines=True).kind != "RPAREN":
                nxt = self._cur()
                raise QuipuSyntaxError(
                    f"Expected ',' or ')' in @table header, got {nxt.kind}", nxt.line, nxt.col
                )
        if not columns:
            raise QuipuSyntaxError(
                "@table must declare at least one column", at_tok.line, at_tok.col
            )
        return columns

    def _parse_named_float_opt(self, opt_name: str, default: float) -> float:
        if self._cur().kind != "COMMA":
            return default
        self._consume("COMMA", skip_newlines=False)
        kw = self._consume("IDENT", skip_newlines=False)
        if kw.value != opt_name:
            raise QuipuSyntaxError(
                f"Expected option {opt_name!r}, got {kw.value!r}", kw.line, kw.col
            )
        self._consume("EQ", skip_newlines=False)
        val = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
        return float(val)

    def _parse_sum_directive(self, fn_tok: _Token) -> TopCordSpec:
        self._consume("LPAREN", skip_newlines=False)
        c_tok = self._consume("IDENT", skip_newlines=False)
        start_row: int | None = None
        end_row: int | None = None
        if self._cur().kind == "COMMA":
            self._require_v2("Figure-8 slice ^sum(col, start, end)", fn_tok)
            self._consume("COMMA", skip_newlines=False)
            s_val = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            self._consume("COMMA", skip_newlines=False)
            e_val = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            if not isinstance(s_val, int) or not isinstance(e_val, int):
                raise QuipuSyntaxError(
                    "^sum slice bounds must be integers", fn_tok.line, fn_tok.col
                )
            start_row, end_row = s_val, e_val
        self._consume("RPAREN", skip_newlines=False)
        self._consume("EQ", skip_newlines=False)
        num = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
        return TopCordSpec(
            kind="sum", column=c_tok.value, expected=num, start_row=start_row, end_row=end_row
        )

    def _parse_band_directive(self) -> TopCordSpec:
        self._consume("LPAREN", skip_newlines=False)
        col = self._consume("IDENT", skip_newlines=False).value
        ratio = "1/2"
        if self._cur().kind == "COMMA":
            self._consume("COMMA", skip_newlines=False)
            kw = self._consume("IDENT", skip_newlines=False)
            if kw.value != "ratio":
                raise QuipuSyntaxError(f"Expected 'ratio', got {kw.value!r}", kw.line, kw.col)
            self._consume("EQ", skip_newlines=False)
            ratio = self._consume("STRING", skip_newlines=False).value
        self._consume("RPAREN", skip_newlines=False)
        self._consume("EQ", skip_newlines=False)
        num = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
        return TopCordSpec(kind="band", column=col, expected=num, ratio=ratio)

    def _parse_v2_top_cord(
        self, kind: str, fn_tok: _Token, layout_holder: list[str | None]
    ) -> TopCordSpec | None:
        if kind == "layout":
            self._consume("EQ", skip_newlines=False)
            layout_holder[0] = self._consume("STRING", skip_newlines=False).value
            return None
        if kind in ("net", "equal_sum"):
            self._consume("LPAREN", skip_newlines=False)
            c1 = self._consume("IDENT", skip_newlines=False).value
            self._consume("COMMA", skip_newlines=False)
            c2 = self._consume("IDENT", skip_newlines=False).value
            self._consume("RPAREN", skip_newlines=False)
            self._consume("EQ", skip_newlines=False)
            num = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            return TopCordSpec(kind=kind, column=c1, end_column=c2, expected=num)
        if kind in ("tol", "quota"):
            default_pct = 5.0 if kind == "tol" else 22.5
            self._consume("LPAREN", skip_newlines=False)
            col = self._consume("IDENT", skip_newlines=False).value
            pct = self._parse_named_float_opt("pct", default_pct)
            self._consume("RPAREN", skip_newlines=False)
            self._consume("EQ", skip_newlines=False)
            num = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            return TopCordSpec(kind=kind, column=col, expected=num, tolerance_pct=pct)
        if kind == "band":
            return self._parse_band_directive()
        raise QuipuSyntaxError(f"Unknown Top-Cord directive ^{kind}", fn_tok.line, fn_tok.col)

    def _parse_single_top_cord(self, layout_holder: list[str | None]) -> TopCordSpec | None:
        self._consume("CARET")
        fn_tok = self._consume("IDENT", skip_newlines=False)
        kind = fn_tok.value
        if kind == "count":
            self._consume("EQ", skip_newlines=False)
            num = _parse_number_token(self._consume("NUMBER", skip_newlines=False))
            if not isinstance(num, int):
                raise QuipuSyntaxError("^count expected integer", fn_tok.line, fn_tok.col)
            return TopCordSpec(kind="count", column=None, expected=num)
        if kind == "sum":
            return self._parse_sum_directive(fn_tok)
        self._require_v2(f"Table directive ^{kind}", fn_tok)
        return self._parse_v2_top_cord(kind, fn_tok, layout_holder)

    def _parse_table_cell(self) -> Any:
        tok = self._consume(skip_newlines=False)
        if tok.kind == "STRING":
            return tok.value
        if tok.kind == "NUMBER":
            return _parse_number_token(tok)
        if tok.kind == "IDENT":
            return _resolve_ident_literal(tok, "table")
        raise QuipuSyntaxError(
            f"Expected scalar @table cell, got {tok.kind} ({tok.value!r})", tok.line, tok.col
        )

    def _collect_top_cords(
        self, top_cords: list[TopCordSpec], layout_holder: list[str | None]
    ) -> None:
        while self._peek(skip_newlines=True).kind == "CARET":
            spec = self._parse_single_top_cord(layout_holder)
            if spec is not None:
                top_cords.append(spec)

    def _parse_table_row(self, col_count: int) -> list[Any]:
        row: list[Any] = []
        for idx in range(col_count):
            row.append(self._parse_table_cell())
            if idx < col_count - 1:
                self._consume("PIPE", skip_newlines=False)
        nxt = self._cur()
        if nxt.kind not in ("NEWLINE", "RBRACE"):
            raise QuipuSyntaxError(
                f"Expected newline or '}}' after @table row, got {nxt.kind}", nxt.line, nxt.col
            )
        return row

    def _parse_table(self, depth: int) -> QuipuTable:
        if depth + 1 > MAX_QUIPU_DEPTH:
            cur = self._cur()
            raise QuipuSyntaxError(
                f"Maximum nesting depth ({MAX_QUIPU_DEPTH}) exceeded", cur.line, cur.col
            )
        at_tok = self._consume("AT")
        tbl_tok = self._consume("IDENT", skip_newlines=False)
        if tbl_tok.value != "table":
            raise QuipuSyntaxError(
                f"Expected '@table', got '@{tbl_tok.value}'", tbl_tok.line, tbl_tok.col
            )
        columns = self._parse_table_columns(at_tok)
        top_cords: list[TopCordSpec] = []
        layout_holder: list[str | None] = [None]
        self._collect_top_cords(top_cords, layout_holder)
        self._consume("LBRACE")
        rows: list[list[Any]] = []
        spacers: list[int] = []
        col_count = len(columns)
        while True:
            self._skip_newlines()
            cur = self._cur()
            if cur.kind == "RBRACE":
                self._consume("RBRACE", skip_newlines=False)
                break
            if cur.kind == "SPACER":
                self._require_v2("Row spacer '---'", cur)
                self._consume("SPACER", skip_newlines=False)
                spacers.append(len(rows))
                continue
            rows.append(self._parse_table_row(col_count))
        self._collect_top_cords(top_cords, layout_holder)
        return QuipuTable(
            columns=columns,
            rows=rows,
            top_cords=top_cords,
            spacer_indices=spacers,
            layout=layout_holder[0],
        )


def parse_quipu(text: str) -> QuipuDocument:
    """Parses QUIPU/1.0 or QUIPU/2.0 (.quipu) wire text into a typed QuipuDocument AST."""
    if not isinstance(text, str):
        raise QuipuSyntaxError("QUIPU input must be str")
    if "\x00" in text:
        raise QuipuSyntaxError("Null byte rejected in QUIPU payload")
    raw_bytes = len(text.encode("utf-8"))
    if raw_bytes > MAX_QUIPU_BYTES:
        raise QuipuSyntaxError(
            f"QUIPU payload exceeds MAX_QUIPU_BYTES ({raw_bytes} > {MAX_QUIPU_BYTES})"
        )
    return _Parser(_tokenize(text)).parse_document()


# -----------------------------------------------------------------------------
# Canonical Serializer & SHA-256 Knot Sealing
# -----------------------------------------------------------------------------


def _append_v2_decorators(meta: CordMeta, parts: list[str]) -> None:
    if meta.attachment is not None:
        parts.append(f"~{meta.attachment.value}")
    if meta.explicit_tier or meta.tier != CordTier.T0:
        parts.append(f"@{meta.tier.value}")
    if meta.polarity is not None:
        parts.append(f"@{meta.polarity.value}")
    if meta.unit is not None:
        parts.append(f"^unit={json.dumps(meta.unit, ensure_ascii=False)}")
    if meta.wrap is not None:
        parts.append(f"^wrap={json.dumps(meta.wrap, ensure_ascii=False)}")
    if meta.nether is not None:
        parts.append(f"^nether={meta.nether}")


def _format_decorators(meta: CordMeta) -> str:
    parts: list[str] = []
    if meta.anchor is not None:
        parts.append(f"&{meta.anchor}")
    if meta.explicit_spin or meta.spin != CordSpin.Z:
        parts.append(f"~{meta.spin.value}")
    _append_v2_decorators(meta, parts)
    if meta.knots is not None:
        parts.append(f"^knots={json.dumps(meta.knots, ensure_ascii=False)}")
    return " ".join(parts)


def _format_key(key: str) -> str:
    if _BARE_KEY_RE.match(key) and key not in _RESERVED_BARE:
        return key
    return json.dumps(key, ensure_ascii=False)


def _format_scalar(val: Any) -> str:
    if val is None:
        return "_"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if not math.isfinite(val):
            raise QuipuSyntaxError(f"Cannot serialize non-finite float {val!r}")
        return repr(val)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    raise QuipuSyntaxError(f"Unsupported scalar type {type(val).__name__}")


def _is_scalar(val: Any) -> bool:
    return val is None or isinstance(val, (bool, int, float, str))


def _format_v2_top_cord(tc: TopCordSpec) -> str:
    if tc.kind in ("net", "equal_sum"):
        return f"^{tc.kind}({tc.column}, {tc.end_column})={tc.expected}"
    if tc.kind in ("tol", "quota"):
        pct_str = f", pct={tc.tolerance_pct}" if tc.tolerance_pct is not None else ""
        return f"^{tc.kind}({tc.column}{pct_str})={tc.expected}"
    if tc.kind == "band":
        ratio_str = f", ratio={json.dumps(tc.ratio, ensure_ascii=False)}" if tc.ratio else ""
        return f"^band({tc.column}{ratio_str})={tc.expected}"
    return ""


def _format_top_cord(tc: TopCordSpec) -> str:
    if tc.kind == "count":
        return f"^count={tc.expected}"
    if tc.kind == "sum":
        if tc.start_row is not None and tc.end_row is not None:
            return f"^sum({tc.column}, {tc.start_row}, {tc.end_row})={tc.expected}"
        return f"^sum({tc.column})={tc.expected}"
    return _format_v2_top_cord(tc)


def _format_table_directives(table: QuipuTable) -> str:
    tc_parts: list[str] = []
    if table.layout is not None:
        tc_parts.append(f"^layout={json.dumps(table.layout, ensure_ascii=False)}")
    for tc in table.top_cords:
        rendered_tc = _format_top_cord(tc)
        if rendered_tc:
            tc_parts.append(rendered_tc)
    return (" " + " ".join(tc_parts)) if tc_parts else ""


def _format_table(table: QuipuTable, indent: int) -> str:
    pad = " " * indent
    cols_str = ", ".join(f"{name}:{ctype}" for name, ctype in table.columns)
    tc_str = _format_table_directives(table)
    if not table.rows and not table.spacer_indices:
        return f"@table({cols_str}){tc_str} {{}}"
    lines = [f"@table({cols_str}){tc_str} {{"]
    spacer_counts: dict[int, int] = {}
    for s_idx in table.spacer_indices:
        spacer_counts[s_idx] = spacer_counts.get(s_idx, 0) + 1
    for r_idx, row in enumerate(table.rows):
        for _ in range(spacer_counts.get(r_idx, 0)):
            lines.append(f"{pad}  ---")
        lines.append(f"{pad}  " + " | ".join(_format_scalar(cell) for cell in row))
    for _ in range(spacer_counts.get(len(table.rows), 0)):
        lines.append(f"{pad}  ---")
    lines.append(f"{pad}}}")
    return "\n".join(lines)


def _format_list_value(val: list[QuipuNode], indent: int, pad: str) -> str:
    if not val:
        return "[]"
    is_short_scalar_list = len(val) <= 4 and all(
        not item.meta.has_annotations() and _is_scalar(item.value) for item in val
    )
    if is_short_scalar_list:
        inline = "[" + ", ".join(_format_scalar(item.value) for item in val) + "]"
        if len(inline) <= 72:
            return inline
    lines = ["["]
    for idx, item in enumerate(val):
        comma = "," if idx < len(val) - 1 else ""
        lines.append(f"{pad}  {_format_node(item, indent + 2)}{comma}")
    lines.append(f"{pad}]")
    return "\n".join(lines)


def _format_value(val: Any, indent: int) -> str:
    pad = " " * indent
    if isinstance(val, QuipuTable):
        return _format_table(val, indent)
    if isinstance(val, CordAlias):
        return f"*{val.target}"
    if isinstance(val, list):
        return _format_list_value(val, indent, pad)
    if isinstance(val, dict):
        if not val:
            return "{}"
        lines = ["{"]
        for key, item in val.items():
            lines.append(_format_map_entry(key, item, indent + 2))
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    return _format_scalar(val)


def _format_map_entry(key: str, item: QuipuNode, indent: int) -> str:
    pad = " " * indent
    k_str = _format_key(key)
    dec = _format_decorators(item.meta)
    prefix = f"{k_str} {dec}" if dec else k_str
    return f"{pad}{prefix}: {_format_value(item.value, indent)}"


def _format_node(node: QuipuNode, indent: int = 0) -> str:
    dec = _format_decorators(node.meta)
    rendered = _format_value(node.value, indent)
    return f"{dec} {rendered}" if dec else rendered


def _format_header_line(doc: QuipuDocument) -> str:
    doc_id_q = json.dumps(doc.doc_id, ensure_ascii=False)
    base = f"~= {doc.version} id={doc_id_q} mode={doc.mode.value}"
    if doc.version != QUIPU_V2:
        return base
    extras: list[str] = []
    if doc.admin_tier is not None:
        extras.append(f"tier={doc.admin_tier.value}")
    if doc.tag is not None:
        extras.append(f"tag={json.dumps(doc.tag, ensure_ascii=False)}")
    if doc.parent is not None:
        extras.append(f"parent={json.dumps(doc.parent, ensure_ascii=False)}")
    if doc.hub is not None:
        extras.append(f"hub={json.dumps(doc.hub, ensure_ascii=False)}")
    return f"{base} {' '.join(extras)}" if extras else base


def serialize_quipu_body(doc: QuipuDocument, *, include_header: bool = True) -> str:
    """Renders canonical QUIPU body text prior to any trailing '=~' cryptographic seal."""
    parts: list[str] = []
    if include_header:
        parts.append(_format_header_line(doc))
        parts.append("")
    if isinstance(doc.root.value, dict) and doc.root.value and not doc.root.meta.has_annotations():
        for key, item in doc.root.value.items():
            parts.append(_format_map_entry(key, item, indent=0))
    else:
        parts.append(_format_node(doc.root, indent=0))
    return "\n".join(parts)


def compute_quipu_seal(body_text: str) -> QuipuSeal:
    """Computes deterministic SHA-256 knot seal over canonical serialized body text."""
    digest = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    return QuipuSeal(knot=f"quipu-{digest[:12]}", sha256=digest, reconciled=True)


def dump_quipu(
    doc: QuipuDocument,
    *,
    recompute_seal: bool | None = None,
    include_header: bool = True,
) -> str:
    """Serializes a QuipuDocument AST to canonical QUIPU/1.0 or QUIPU/2.0 wire text."""
    body = serialize_quipu_body(doc, include_header=include_header)
    should_recompute = (doc.mode == QuipuMode.SEALED) if recompute_seal is None else recompute_seal
    seal: QuipuSeal | None = None
    if should_recompute:
        seal_body = body if include_header else serialize_quipu_body(doc, include_header=True)
        seal = compute_quipu_seal(seal_body)
        doc.seal = seal
    elif doc.seal is not None:
        seal = doc.seal
    if seal is not None and include_header:
        rec_str = "true" if seal.reconciled else "false"
        seal_line = (
            f"=~ knot={json.dumps(seal.knot, ensure_ascii=False)} "
            f"sha256={json.dumps(seal.sha256, ensure_ascii=False)} reconciled={rec_str}"
        )
        return f"{body}\n\n{seal_line}\n"
    return f"{body}\n"


# -----------------------------------------------------------------------------
# Lossless JSON / Python Data Isomorphism
# -----------------------------------------------------------------------------


def _is_tabular_record_list(items: list[Any]) -> bool:
    if len(items) < 2 or not all(isinstance(r, dict) for r in items):
        return False
    first_keys = tuple(items[0].keys())
    if not first_keys or len(first_keys) > 32:
        return False
    valid_keys = all(
        isinstance(k, str) and _BARE_KEY_RE.match(k) and k not in _RESERVED_BARE for k in first_keys
    )
    if not valid_keys:
        return False
    return all(
        tuple(rec.keys()) == first_keys and all(is_valid_scalar_for_table(v) for v in rec.values())
        for rec in items
    )


def _python_container_to_node(
    val: list[Any] | dict[Any, Any],
    *,
    auto_table: bool,
    default_spin: CordSpin,
    default_tier: CordTier,
    depth: int,
    meta: CordMeta,
) -> QuipuNode:
    if isinstance(val, list):
        if auto_table and _is_tabular_record_list(val):
            return QuipuNode(value=QuipuTable.from_records(val), meta=meta)
        children = [
            _python_to_node(
                item,
                auto_table=auto_table,
                default_spin=default_spin,
                default_tier=default_tier,
                depth=depth + 1,
            )
            for item in val
        ]
        return QuipuNode(value=children, meta=meta)
    mapped: dict[str, QuipuNode] = {}
    for k, v in val.items():
        if not isinstance(k, str):
            raise QuipuSyntaxError(f"Map keys must be str, got {type(k).__name__}")
        mapped[k] = _python_to_node(
            v,
            auto_table=auto_table,
            default_spin=default_spin,
            default_tier=default_tier,
            depth=depth + 1,
        )
    return QuipuNode(value=mapped, meta=meta)


def _python_to_node(
    val: Any,
    *,
    auto_table: bool,
    default_spin: CordSpin,
    default_tier: CordTier,
    depth: int,
) -> QuipuNode:
    if depth > MAX_QUIPU_DEPTH:
        raise QuipuSyntaxError(f"Input exceeds MAX_QUIPU_DEPTH ({MAX_QUIPU_DEPTH})")
    meta = CordMeta(spin=default_spin, tier=default_tier)
    if val is None or isinstance(val, (bool, int, str)):
        return QuipuNode(value=val, meta=meta)
    if isinstance(val, float):
        if not math.isfinite(val):
            raise QuipuSyntaxError(f"Non-finite float {val!r} is not representable in QUIPU/JSON")
        return QuipuNode(value=val, meta=meta)
    if isinstance(val, (list, dict)):
        return _python_container_to_node(
            val,
            auto_table=auto_table,
            default_spin=default_spin,
            default_tier=default_tier,
            depth=depth,
            meta=meta,
        )
    raise QuipuSyntaxError(f"Unsupported Python value type {type(val).__name__}")


def data_to_quipu(
    data: Any,
    *,
    doc_id: str = "root",
    mode: str = "sealed",
    auto_table: bool = True,
    default_spin: str = "Z",
    default_tier: str = "T0",
    version: str = DEFAULT_QUIPU_VERSION,
) -> QuipuDocument:
    """Builds a QuipuDocument AST from any JSON-compatible Python data structure."""
    resolved_ver = normalize_quipu_version(version)
    qmode = QuipuMode(mode)
    root = _python_to_node(
        data,
        auto_table=auto_table,
        default_spin=CordSpin(default_spin),
        default_tier=CordTier(default_tier),
        depth=0,
    )
    doc = QuipuDocument(doc_id=doc_id, mode=qmode, version=resolved_ver, root=root)
    if qmode == QuipuMode.SEALED:
        doc.seal = compute_quipu_seal(serialize_quipu_body(doc, include_header=True))
    return doc


def _collect_anchors_into(node: QuipuNode, anchors: dict[str, QuipuNode]) -> None:
    if node.meta.anchor:
        anchors[node.meta.anchor] = node
    if isinstance(node.value, list):
        for child in node.value:
            _collect_anchors_into(child, anchors)
    elif isinstance(node.value, dict):
        for child in node.value.values():
            _collect_anchors_into(child, anchors)


def _resolve_alias_data(
    alias: CordAlias,
    depth: int,
    *,
    resolve_aliases: bool,
    anchors: dict[str, QuipuNode],
    resolving: set[str],
    state: list[int],
) -> Any:
    if not resolve_aliases:
        return f"*{alias.target}"
    if alias.target not in anchors:
        raise QuipuSyntaxError(f"Unresolved cord alias *{alias.target}")
    if alias.target in resolving:
        raise QuipuSyntaxError(f"Cyclic alias reference involving *{alias.target}")
    state[0] += 1
    if state[0] > MAX_ALIAS_EXPANSIONS:
        raise QuipuSyntaxError(
            f"Alias expansion budget exceeded ({MAX_ALIAS_EXPANSIONS}, CWE-776 guard)"
        )
    resolving.add(alias.target)
    try:
        return _decode_node_data(
            anchors[alias.target],
            depth + 1,
            resolve_aliases=resolve_aliases,
            anchors=anchors,
            resolving=resolving,
            state=state,
        )
    finally:
        resolving.discard(alias.target)


def _decode_node_data(
    node: QuipuNode,
    depth: int,
    *,
    resolve_aliases: bool,
    anchors: dict[str, QuipuNode],
    resolving: set[str],
    state: list[int],
) -> Any:
    if depth > MAX_QUIPU_DEPTH:
        raise QuipuSyntaxError(f"Decoded structure exceeds MAX_QUIPU_DEPTH ({MAX_QUIPU_DEPTH})")
    v = node.value
    if isinstance(v, QuipuTable):
        return v.to_records()
    if isinstance(v, CordAlias):
        return _resolve_alias_data(
            v,
            depth,
            resolve_aliases=resolve_aliases,
            anchors=anchors,
            resolving=resolving,
            state=state,
        )
    if isinstance(v, list):
        return [
            _decode_node_data(
                child,
                depth + 1,
                resolve_aliases=resolve_aliases,
                anchors=anchors,
                resolving=resolving,
                state=state,
            )
            for child in v
        ]
    if isinstance(v, dict):
        return {
            k: _decode_node_data(
                child,
                depth + 1,
                resolve_aliases=resolve_aliases,
                anchors=anchors,
                resolving=resolving,
                state=state,
            )
            for k, child in v.items()
        }
    return v


def quipu_to_data(doc: QuipuDocument, *, resolve_aliases: bool = True) -> Any:
    """Extracts standard Python objects (JSON-isomorphic) from a QuipuDocument AST."""
    anchors: dict[str, QuipuNode] = {}
    _collect_anchors_into(doc.root, anchors)
    return _decode_node_data(
        doc.root,
        0,
        resolve_aliases=resolve_aliases,
        anchors=anchors,
        resolving=set(),
        state=[0],
    )


def dumps_quipu(
    data: Any,
    *,
    doc_id: str = "root",
    mode: str = "sealed",
    auto_table: bool = True,
    default_spin: str = "Z",
    default_tier: str = "T0",
    include_header: bool = True,
    version: str = DEFAULT_QUIPU_VERSION,
) -> str:
    """Serializes arbitrary JSON-compatible Python data directly to QUIPU wire text."""
    doc = data_to_quipu(
        data,
        doc_id=doc_id,
        mode=mode,
        auto_table=auto_table,
        default_spin=default_spin,
        default_tier=default_tier,
        version=version,
    )
    return dump_quipu(
        doc,
        recompute_seal=(doc.mode == QuipuMode.SEALED),
        include_header=include_header,
    )


def loads_quipu(text: str, *, resolve_aliases: bool = True) -> Any:
    """Parses QUIPU/1.0 or QUIPU/2.0 wire text and returns standard Python data."""
    return quipu_to_data(parse_quipu(text), resolve_aliases=resolve_aliases)


def json_to_quipu(
    json_text: str,
    *,
    doc_id: str = "root",
    mode: str = "sealed",
    auto_table: bool = True,
    version: str = DEFAULT_QUIPU_VERSION,
) -> str:
    """Losslessly converts a JSON string into canonical QUIPU wire format."""
    return dumps_quipu(
        json.loads(json_text),
        doc_id=doc_id,
        mode=mode,
        auto_table=auto_table,
        version=version,
    )


def quipu_to_json(quipu_text: str, *, indent: int | None = 2) -> str:
    """Losslessly converts a QUIPU/1.0 or QUIPU/2.0 string into canonical JSON."""
    return json.dumps(loads_quipu(quipu_text), indent=indent, ensure_ascii=False)


def _sum_table_ints(table: QuipuTable) -> int:
    return sum(
        cell
        for row in table.rows
        for cell in row
        if isinstance(cell, int) and not isinstance(cell, bool)
    )


def _walk_micro_children(val: Any, stats: list[int]) -> None:
    if isinstance(val, list):
        for child in val:
            _collect_micro_stats(child, stats)
    elif isinstance(val, dict):
        for child in val.values():
            _collect_micro_stats(child, stats)


def _collect_micro_stats(node: QuipuNode, stats: list[int]) -> None:
    stats[2] += 1
    if node.meta.spin == CordSpin.S:
        stats[3] += 1
    if node.meta.tier in (CordTier.T2, CordTier.T3):
        stats[4] += 1
    val = node.value
    if isinstance(val, QuipuTable):
        stats[0] += 1
        stats[1] += len(val.rows)
        stats[5] += _sum_table_ints(val)
    elif isinstance(val, int) and not isinstance(val, bool):
        stats[5] += val
    else:
        _walk_micro_children(val, stats)


def render_quipu_micro(doc: QuipuDocument) -> str:
    """Renders an ultra-compact base-10 knot micro-notation summary line."""
    stats = [0, 0, 0, 0, 0, 0]  # [tables, rows, cords, s_cords, tainted, numeric_sum]
    _collect_micro_stats(doc.root, stats)
    knot = doc.seal.knot if doc.seal else "unsealed"
    u7 = encode_urton_7bit(
        doc.root.meta.spin,
        doc.root.meta.tier,
        has_numeric=(stats[5] != 0),
        is_table=(stats[0] > 0),
    )
    knots_sum = encode_incan_knots(stats[5])
    extra = ""
    if doc.version == QUIPU_V2:
        u14 = encode_urton_14bit(
            doc.root.meta, has_numeric=(stats[5] != 0), is_table=(stats[0] > 0)
        )
        tier_tag = f" tier={doc.admin_tier.value}" if doc.admin_tier else ""
        extra = f"{tier_tag} u14={u14}"
    return (
        f"[{doc.version} id={doc.doc_id} mode={doc.mode.value} knot={knot} u7={u7}{extra}] "
        f"cords={stats[2]} tables={stats[0]} rows={stats[1]} S={stats[3]} "
        f"T2+={stats[4]} Q^={knots_sum}"
    )


MAX_ASCII_CHARS = 8000


def _ascii_meta_badge(meta: CordMeta) -> str:
    """Builds a compact visual metadata badge for a cord node."""
    parts: list[str] = []
    flags = (
        (f"&{meta.anchor}", bool(meta.anchor)),
        (f"~{meta.spin.value}", meta.explicit_spin or meta.spin != CordSpin.Z),
        (f"~{meta.attachment.value}" if meta.attachment else "", meta.attachment is not None),
        (f"@{meta.tier.value}", meta.explicit_tier or meta.tier != CordTier.T0),
        (f"@{meta.polarity.value}" if meta.polarity else "", meta.polarity is not None),
    )
    parts.extend(label for label, active in flags if active)
    for key in ("unit", "wrap", "nether"):
        val = getattr(meta, key)
        if val is not None:
            val_s = json.dumps(val, ensure_ascii=False) if isinstance(val, str) else str(val)
            parts.append(f"^{key}={val_s}")
    return f" [{' '.join(parts)}]" if parts else ""


def _ascii_tier_glyph(tok: str) -> str | None:
    if tok == "1E":
        return "⟨1E⟩"
    suffix, digits = tok[-1], tok[:-1]
    if not digits.isdigit():
        return tok
    digit = int(digits)
    if digit == 0:
        return None
    if suffix == "U":
        return "●(1U)" if digit == 1 else f"≈{digit}T≈({tok})"
    beads = "●" * digit if digit <= 5 else f"●×{digit}"
    return f"{beads}({tok})"


def _ascii_knot_glyphs(val: int, explicit_knots: str | None) -> str:
    knot_str = explicit_knots or encode_incan_knots(abs(val))
    glyphs = [g for g in (_ascii_tier_glyph(t) for t in knot_str.split("-")) if g is not None]
    body = " -> ".join(glyphs) if glyphs else "[0 gap]"
    return f"{body} [{knot_str}]"


def _collect_ascii_top_cords(node: QuipuNode, label: str, out: list[str]) -> None:
    val = node.value
    if isinstance(val, QuipuTable) and val.top_cords:
        joined = " | ".join(tc for tc in (_format_top_cord(t) for t in val.top_cords) if tc)
        out.append(f"  ▲ [{label}] {joined}")
    elif isinstance(val, dict):
        for k, child in val.items():
            _collect_ascii_top_cords(child, f"{label}.{k}" if label else str(k), out)
    elif isinstance(val, list):
        for idx, child in enumerate(val):
            _collect_ascii_top_cords(child, f"{label}[{idx}]", out)


def _render_ascii_table(
    lines: list[str], head: str, child_pad: str, table: QuipuTable, max_rows: int
) -> None:
    cols_s = ", ".join(f"{name}:{ctype}" for name, ctype in table.columns)
    lines.append(f"{head}: @table({cols_s}) [{len(table.rows)} rows]")
    limit = min(len(table.rows), max_rows)
    spacer_set = set(table.spacer_indices)
    for idx in range(limit):
        if idx in spacer_set:
            lines.append(f"{child_pad}├── ┄┄┄ [--- band spacer] ┄┄┄")
        row_s = " | ".join(_format_scalar(cell) for cell in table.rows[idx])
        is_tail = idx == len(table.rows) - 1 and len(table.rows) <= max_rows
        lines.append(f"{child_pad}{'└──' if is_tail else '├──'} [{idx}] {row_s}")
    if len(table.rows) > max_rows:
        lines.append(f"{child_pad}└── ... (+{len(table.rows) - max_rows} more rows)")


def _render_ascii_container(
    lines: list[str],
    head: str,
    child_pad: str,
    val: dict[str, QuipuNode] | list[QuipuNode],
    depth: int,
    max_rows: int,
) -> None:
    items = (
        list(val.items()) if isinstance(val, dict) else [(f"[{i}]", v) for i, v in enumerate(val)]
    )
    lines.append(
        f"{head}: {{{len(items)} items}}"
        if isinstance(val, dict)
        else f"{head}: [{len(items)} items]"
    )
    if depth >= 6:
        lines.append(f"{child_pad}└── ... (max depth reached)")
        return
    shown = items[:max_rows]
    has_more = len(items) > max_rows
    for idx, (child_key, child_node) in enumerate(shown):
        is_last = idx == len(shown) - 1 and not has_more
        _render_ascii_node(
            lines, child_pad, str(child_key), child_node, depth + 1, max_rows, is_last
        )
    if has_more:
        lines.append(f"{child_pad}└── ... (+{len(items) - max_rows} more items)")


def _render_ascii_node(
    lines: list[str],
    pad: str,
    label: str,
    node: QuipuNode,
    depth: int,
    max_rows: int,
    is_last: bool,
) -> None:
    badge = _ascii_meta_badge(node.meta)
    if depth == 0:
        head, child_pad = f"  │── Pendant {label}{badge}", "  │   "
    else:
        conn = "└──" if is_last else "├──"
        head = f"{pad}{conn} ↳ Subsidiary {label}{badge}"
        child_pad = pad + ("    " if is_last else "│   ")
    val = node.value
    if isinstance(val, CordAlias):
        lines.append(f"{head}: ⤴ *{val.target} (alias)")
    elif isinstance(val, QuipuTable):
        _render_ascii_table(lines, head, child_pad, val, max_rows)
    elif isinstance(val, (dict, list)):
        _render_ascii_container(lines, head, child_pad, val, depth, max_rows)
    elif isinstance(val, int) and not isinstance(val, bool):
        lines.append(f"{head}: val={val}")
        lines.append(f"{child_pad}└── Knots: {_ascii_knot_glyphs(val, node.meta.knots)}")
    else:
        lines.append(f"{head}: {_format_scalar(val)}")


def _ascii_header_line(doc: QuipuDocument) -> str:
    knot = doc.seal.knot if doc.seal else "unsealed"
    parts = [f"mode={doc.mode.value}"]
    if doc.admin_tier:
        parts.append(f"tier={doc.admin_tier.value}")
    if doc.tag:
        parts.append(f"tag={json.dumps(doc.tag, ensure_ascii=False)}")
    if doc.hub:
        parts.append(f"hub={json.dumps(doc.hub, ensure_ascii=False)}")
    meta_s = " ".join(parts)
    return f"=== {doc.version}: {doc.doc_id} [{meta_s} | knot={knot}] ==="


def render_quipu_ascii(
    doc_or_text: QuipuDocument | str,
    *,
    max_rows: int = 8,
    max_chars: int = MAX_ASCII_CHARS,
) -> str:
    """Renders a visual CLI cord diagram with Top Cords, Primary Cord, Pendants & Knots."""
    doc = parse_quipu(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    lines = [_ascii_header_line(doc), ""]
    top_lines: list[str] = []
    _collect_ascii_top_cords(
        doc.root, "root" if not isinstance(doc.root.value, dict) else "", top_lines
    )
    if top_lines:
        lines.append("  [TOP CORDS: UPWARD RECONCILIATIONS]")
        lines.extend(top_lines)
        lines.append("  │")
    lines.append("(LOOP)" + "═" * 74 + "(TASSEL)")
    lines.append("[Head]" + " " * 19 + "PRIMARY CORD (HORIZONTAL TRUNK)" + " " * 24 + "[Tail]")
    lines.append("")
    if isinstance(doc.root.value, dict):
        keys = list(doc.root.value.keys())
        for idx, k in enumerate(keys):
            _render_ascii_node(lines, "", k, doc.root.value[k], 0, max_rows, idx == len(keys) - 1)
    else:
        _render_ascii_node(lines, "", "root", doc.root, 0, max_rows, True)
    lines.append("═" * 88)
    out = "\n".join(lines)
    if len(out) > max_chars:
        return out[: max(64, max_chars - 32)] + "\n... [TRUNCATED_TO_MAX_ASCII_CHARS]"
    return out


def _sample_v2_metas(
    is_v2: bool,
) -> tuple[list[TopCordSpec], CordMeta, CordMeta, CordMeta, CordMeta]:
    top_cords = [
        TopCordSpec(kind="count", column=None, expected=3),
        TopCordSpec(kind="sum", column="tokens", expected=176),
    ]
    if is_v2:
        top_cords.append(TopCordSpec(kind="tol", column="tokens", expected=170, tolerance_pct=5.0))
        return (
            top_cords,
            CordMeta(knots="0M-0C-0D-3U", unit="attempts"),
            CordMeta(attachment=CordAttachment.R, polarity=CordPolarity.WHITE),
            CordMeta(spin=CordSpin.Z, tier=CordTier.T0, polarity=CordPolarity.WHITE, unit="tokens"),
            CordMeta(
                spin=CordSpin.S,
                attachment=CordAttachment.V,
                tier=CordTier.T2,
                polarity=CordPolarity.DARK,
                explicit_spin=True,
                explicit_tier=True,
            ),
        )
    return (
        top_cords,
        CordMeta(knots="0M-0C-0D-3U"),
        CordMeta(),
        CordMeta(spin=CordSpin.Z, tier=CordTier.T0),
        CordMeta(spin=CordSpin.S, tier=CordTier.T2, explicit_spin=True, explicit_tier=True),
    )


def _sample_quipu_doc(resolved: str) -> QuipuDocument:
    is_v2 = resolved == QUIPU_V2
    top_cords, retries_meta, service_meta, metrics_meta, webhook_meta = _sample_v2_metas(is_v2)
    root = QuipuNode(
        value={
            "service": QuipuNode(value="edge-gateway", meta=service_meta),
            "version": QuipuNode(value="2026.11.25" if is_v2 else "2026.11.14"),
            "defaults": QuipuNode(
                value={
                    "region": QuipuNode(value="eu-central-1"),
                    "retries": QuipuNode(value=3, meta=retries_meta),
                },
                meta=CordMeta(
                    spin=CordSpin.Z,
                    tier=CordTier.T0,
                    anchor="prod_defaults",
                    explicit_spin=True,
                    explicit_tier=True,
                ),
            ),
            "active_defaults": QuipuNode(value=CordAlias(target="prod_defaults")),
            "metrics": QuipuNode(
                value=QuipuTable(
                    columns=[("stage", "str"), ("tokens", "int"), ("passed", "bool")],
                    rows=[
                        ["lint_check", 42, True],
                        ["unit_tests", 118, True],
                        ["verify_seal", 16, True],
                    ],
                    top_cords=top_cords,
                    layout="banded" if is_v2 else None,
                ),
                meta=metrics_meta,
            ),
            "external_webhook": QuipuNode(
                value={"url": QuipuNode(value="https://hooks.example.org/ingest")},
                meta=webhook_meta,
            ),
        }
    )
    return QuipuDocument(
        doc_id="service.release.manifest",
        mode=QuipuMode.SEALED,
        version=resolved,
        admin_tier=AdminTier.WORKING if is_v2 else None,
        tag="release_telemetry" if is_v2 else None,
        root=root,
    )


def sample_quipu(version: str = DEFAULT_QUIPU_VERSION) -> str:
    """Returns a canonical, verified QUIPU/2.0 (default) or QUIPU/1.0 example document."""
    return dump_quipu(_sample_quipu_doc(normalize_quipu_version(version)), recompute_seal=True)


def load(fp: IO[str], *, resolve_aliases: bool = True) -> Any:
    """Reads and decodes a .quipu text stream into standard Python objects."""
    return loads_quipu(fp.read(), resolve_aliases=resolve_aliases)


def dump(
    data: Any,
    fp: IO[str],
    *,
    doc_id: str = "root",
    mode: str = "sealed",
    auto_table: bool = True,
    version: str = DEFAULT_QUIPU_VERSION,
) -> None:
    """Serializes Python data as canonical QUIPU wire text into a writable text stream."""
    fp.write(dumps_quipu(data, doc_id=doc_id, mode=mode, auto_table=auto_table, version=version))


loads = loads_quipu
dumps = dumps_quipu
parse = parse_quipu
draw_quipu = render_quipu_ascii
draw = render_quipu_ascii
