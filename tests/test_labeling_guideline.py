"""라벨링 지침 동결 — (A) §6.2. 지침 파일이 표의 해시와 같아야 한다. 변경 = 새 지침 버전 + 새 데이터셋 버전(G-3)."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.eval.frozen_rulesets import FROZEN_GUIDELINES, guideline_is_frozen
from tools.mutation_guard import apply_mutation, copy_with_mutation
from tests.test_rule_wiring import _run_mutant

REPO_ROOT = Path(__file__).resolve().parents[1]
GUIDELINE = REPO_ROOT / "docs" / "labeling-guideline.md"


def test_guideline_matches_its_frozen_hash():
    assert guideline_is_frozen(GUIDELINE, "v1")


def test_guideline_head_names_the_frozen_version():
    assert "버전: v1." in GUIDELINE.read_text(encoding="utf-8") and "v1" in FROZEN_GUIDELINES


def test_one_changed_line_breaks_the_freeze(tmp_path):
    copy = tmp_path / "labeling-guideline.md"
    copy.write_text(apply_mutation(GUIDELINE.read_text(encoding="utf-8"), "- **O-3:**", "- **O-3 변경:**"), encoding="utf-8")
    assert not guideline_is_frozen(copy, "v1")


def test_line_endings_do_not_break_the_freeze(tmp_path):
    lf = GUIDELINE.read_bytes().replace(b"\r\n", b"\n")
    copy = tmp_path / "labeling-guideline.md"
    copy.write_bytes(lf.replace(b"\n", b"\r\n"))
    assert guideline_is_frozen(copy, "v1")


def test_unknown_version_is_not_frozen():
    assert not guideline_is_frozen(GUIDELINE, "v0")


@pytest.mark.parametrize("old, new, node", [
    ("    return frozen_file_hash(path) == FROZEN_GUIDELINES.get(version)\n", "    return True\n",
     "tests/test_labeling_guideline.py::test_one_changed_line_breaks_the_freeze"),
], ids=["freeze_check_off"])
def test_freeze_check_is_load_bearing_under_verified_mutation(tmp_path, old, new, node):
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, "tools/eval/frozen_rulesets.py", old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], "tools.eval.frozen_rulesets", [node], mutant)
