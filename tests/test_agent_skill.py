"""Validation tests for the quipu AI agent skill package and reference examples."""

from __future__ import annotations

import re
from pathlib import Path

from quipu.codec import compute_quipu_seal, parse_quipu, serialize_quipu_body
from quipu.verifier import verify_quipu

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "skills" / "quipu"
SKILL_MD = SKILL_DIR / "SKILL.md"
ROOT_SKILL_MD = REPO_ROOT / "SKILL.md"

_QUIPU_FENCE_RE = re.compile(r"```quipu\n(.*?)```", re.DOTALL)
_MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]*)?\)")


def _extract_frontmatter(text: str) -> str:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match is not None, "SKILL.md must start with YAML frontmatter"
    return match.group(1)


def test_skill_structure_frontmatter_and_parity() -> None:
    assert SKILL_MD.is_file(), f"Missing {SKILL_MD}"
    assert ROOT_SKILL_MD.is_file(), f"Missing {ROOT_SKILL_MD}"

    skill_text = SKILL_MD.read_text(encoding="utf-8")
    root_text = ROOT_SKILL_MD.read_text(encoding="utf-8")

    assert len(skill_text.encode("utf-8")) < 12_000, "SKILL.md exceeded compact size cap"
    fm = _extract_frontmatter(skill_text)
    assert re.search(r"^name:\s*quipu\s*$", fm, re.MULTILINE)
    assert re.search(r"^description:\s*.+\S", fm, re.MULTILINE)

    for required_heading in (
        "## Prerequisites & Setup",
        "## When to Use",
        "## When Not to Use",
        "## Task Routing & Ordered Workflow",
        "## Critical Rules for AI Agents",
        "## Output Contract",
        "## Limitations",
    ):
        assert required_heading in skill_text, f"Missing heading: {required_heading}"

    # Root SKILL.md stays identically synchronized with rewritten reference path prefix
    expected_root = skill_text.replace("(references/", "(skills/quipu/references/")
    assert root_text == expected_root, "Root SKILL.md is out of sync with skills/quipu/SKILL.md"

    for base_dir, md_path in ((SKILL_DIR, SKILL_MD), (REPO_ROOT, ROOT_SKILL_MD)):
        text = md_path.read_text(encoding="utf-8")
        for target in _MD_LINK_RE.findall(text):
            if target.startswith(("http://", "https://")):
                continue
            resolved = base_dir / target
            assert resolved.is_file(), f"Broken markdown link {target!r} in {md_path}"


def test_skill_workflow_examples_and_antipatterns_verify() -> None:
    workflows_md = SKILL_DIR / "references" / "agent-workflows-and-antipatterns.md"
    assert workflows_md.is_file()
    content = workflows_md.read_text(encoding="utf-8")

    blocks = _QUIPU_FENCE_RE.findall(content)
    positive_blocks = [b for b in blocks if not b.lstrip().startswith("# ANTI-PATTERN")]
    antipattern_blocks = [b for b in blocks if b.lstrip().startswith("# ANTI-PATTERN")]

    assert len(positive_blocks) >= 2, "Expected happy-path and secure-variant examples"
    assert len(antipattern_blocks) >= 3, "Expected anti-pattern examples"

    for idx, wire in enumerate(positive_blocks, start=1):
        assert "<LOCK_" not in wire, f"Unlocked placeholder seal in positive example #{idx}"
        doc = parse_quipu(wire)
        report = verify_quipu(wire)
        assert report["valid"] is True, f"Positive example #{idx} failed: {report['findings']}"
        if doc.seal is not None:
            expected_seal = compute_quipu_seal(serialize_quipu_body(doc, include_header=True))
            assert doc.seal.sha256 == expected_seal.sha256

    for idx, wire in enumerate(antipattern_blocks, start=1):
        report = verify_quipu(wire)
        assert report["valid"] is False, f"Anti-pattern #{idx} unexpectedly passed verification"
