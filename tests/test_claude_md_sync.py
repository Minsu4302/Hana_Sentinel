"""`claude_md_sync_check` — CLAUDE.md 금지선 색인 ↔ (A) §1.4. (A) §1.4, §3.1.

'위조 거부'로 증명한다: 실제 CLAUDE.md·(A) 텍스트의 복사본에 어긋남을 심으면 검사가 잡는다 — 색인 쪽(키 삭제·추가·이동,
정의처 바꿔치기, 키 소절 틀림, N줄 삭제·중복, N5 키 추가·'없음' 삭제)과 (A) 쪽(§3에 없는 키, ⓑ행의 ⓑ 해석 키 제거,
N8의 코드 표지 키 제거). 읽을 수 없는 형식은 통과가 아니라 오류다(fail-closed). 대조: 실제 레포는 위반 0.
범위: §1.4 자체의 완전성은 검사하지 않는다(리뷰 몫). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.guardrails import ban_index
from tools.guardrails.ban_index import BanIndexError, check, check_repo
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
# 레포의 실제 문서 — 모듈 상수가 아니라 이 테스트 파일 기준(변이 실행에서는 tools/만 변이본이고 문서는 레포 것)
DESIGN = (REPO_ROOT / "docs" / "design-decision.md").read_text(encoding="utf-8")
CLAUDE = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")


def _line(text: str, n: str) -> str:
    [line] = [x for x in text.splitlines() if x.startswith(f"- **{n} ")]
    return line


def _edit_line(text: str, n: str, old: str, new: str) -> str:
    line = _line(text, n)
    assert line.count(old) == 1, (n, old)
    return text.replace(line, line.replace(old, new))


def _ban_row(text: str, n: str) -> str:
    [row] = [x for x in text.splitlines() if x.startswith(f"| {n} |")]
    return row


def _edit_row(text: str, n: str, old: str, new: str) -> str:
    row = _ban_row(text, n)
    assert row.count(old) == 1, (n, old)
    return text.replace(row, row.replace(old, new))


def _codes(problems: list[str]) -> set[str]:
    return {p.split("@")[0].split(":")[0] for p in problems}


# ── 대조 ─────────────────────────────────────────────────────────

def test_repository_index_matches_section_1_4():
    assert check(DESIGN, CLAUDE) == []


def test_repo_entry_point_reads_the_real_documents():
    assert ban_index.DESIGN_DOC == REPO_ROOT / "docs" / "design-decision.md" and ban_index.CLAUDE_MD == REPO_ROOT / "CLAUDE.md"
    assert check_repo() == []


# ── 위조 거부: CLAUDE.md 색인 쪽 ────────────────────────────────────────

CLAUDE_FORGERIES = {
    "key_deleted": (lambda t: _edit_line(t, "N1", ", `masker_no_send`(§3.1)", ""), {"index_keys_differ@N1"}),
    "unknown_key_added": (lambda t: _edit_line(t, "N2", "`masker_no_send`(§3.1)", "`masker_no_send`(§3.1), `no_such_key`(§3.1)"),
                          {"index_keys_differ@N2"}),
    "key_moved_to_another_line": (lambda t: _edit_line(_edit_line(t, "N4", ", `input_schema_gate`(§3.2)", ""), "N3",
                                                       "`java_logic_isolation`(§3.2)",
                                                       "`java_logic_isolation`(§3.2), `input_schema_gate`(§3.2)"),
                                  {"index_keys_differ@N3", "index_keys_differ@N4"}),
    "definitions_swapped_a_b": (lambda t: _edit_line(_edit_line(t, "N1", "정의처: §1.3 ⓑ", "정의처: §1.3 ⓐ"), "N2",
                                                     "정의처: §1.3 ⓐ", "정의처: §1.3 ⓑ"),
                                {"index_definitions_differ@N1", "index_definitions_differ@N2"}),
    "definition_coarsened": (lambda t: _edit_line(t, "N4", "정의처: §3.2", "정의처: §3"), {"index_definitions_differ@N4"}),
    "key_section_wrong": (lambda t: _edit_line(t, "N4", "`engine_burp_isolation`(§3.2)", "`engine_burp_isolation`(§3.1)"),
                          {"index_key_section_differs@N4:engine_burp_isolation"}),
    "line_deleted": (lambda t: t.replace(_line(t, "N6") + "\n", ""), {"index_missing_line@N6"}),
    "key_added_to_n5": (lambda t: _edit_line(t, "N5", "키: 없음(기계 강제 불가 — 정책·리뷰)", "키: `secret_scan_hook`(§3.3)"),
                        {"index_keys_differ@N5", "index_no_keys_marker@N5"}),
}


@pytest.mark.parametrize("name", sorted(CLAUDE_FORGERIES))
def test_forged_index_is_caught(name):
    forge, expected = CLAUDE_FORGERIES[name]
    problems = check(DESIGN, forge(CLAUDE))
    assert set(problems) == expected


def test_n5_without_the_none_marker_is_a_format_error():
    forged = _edit_line(CLAUDE, "N5", "키: 없음(기계 강제 불가 — 정책·리뷰)", "키: (기계 강제 불가 — 정책·리뷰)")
    with pytest.raises(BanIndexError, match="index_key_without_section"):
        check(DESIGN, forged)


def test_duplicated_index_line_is_an_error():
    forged = CLAUDE.replace(_line(CLAUDE, "N8"), _line(CLAUDE, "N8") + "\n" + _line(CLAUDE, "N8"))
    with pytest.raises(BanIndexError, match="index_duplicate_n"):
        check(DESIGN, forged)


# ── 위조 거부: (A) 쪽 ─────────────────────────────────────────────

def test_ban_table_key_missing_from_section3_is_caught():
    design = _edit_row(DESIGN, "N2", "`masker_no_send`", "`no_such_key`")
    claude = _edit_line(CLAUDE, "N2", "`masker_no_send`(§3.1)", "`no_such_key`(§3.1)")
    assert check(design, claude) == ["ban_key_not_in_section3@N2:no_such_key"]


def test_b_row_dropping_a_b_interpretation_key_is_caught():
    design = _edit_row(DESIGN, "N1", "`egress_static_check`, ", "")
    claude = _edit_line(CLAUDE, "N1", "`egress_static_check`(§3.1), ", "")
    assert check(design, claude) == ["b_row_misses_b_interpretation_key:egress_static_check"]


def test_n8_dropping_the_coded_section3_key_is_caught():
    design = _edit_row(DESIGN, "N8", "`no_autopatch_apply`", "(없음)")
    claude = _edit_line(CLAUDE, "N8", "`no_autopatch_apply`(§3.1)", "없음(모의)")
    assert check(design, claude) == ["coded_section3_key_not_in_ban_row:no_autopatch_apply(ⓓ)"]


# ── 형식 오류는 통과가 아니다(fail-closed) ─────────────────────────────────

FORMAT_ERRORS = {
    "backtick_key_in_remainder": (lambda d, c: (d, _edit_line(c, "N8", "(재론: 권고 초안 허용)", "(재론: `masker_no_send` 참고)")),
                                  "index_key_in_remainder"),
    "duplicate_key_in_line": (lambda d, c: (d, _edit_line(c, "N2", "`masker_no_send`(§3.1)",
                                                          "`masker_no_send`(§3.1), `masker_no_send`(§3.1)")),
                              "index_duplicate_key"),
    "duplicate_definition_in_line": (lambda d, c: (d, _edit_line(c, "N7", "정의처: §1.3 ⓕ, §3.3", "정의처: §1.3 ⓕ, §1.3 ⓕ")),
                                     "index_duplicate_definition"),
    "anchor_removed": (lambda d, c: (d, _edit_line(c, "N3", " → 정의처: ", " -> 정의처: ")), "index_anchor"),
    "anchor_twice": (lambda d, c: (d, _edit_line(c, "N3", "`java_logic_isolation`(§3.2)",
                                                 "`java_logic_isolation`(§3.2) → 정의처: §3.2")), "index_anchor"),
    "keys_separator_missing": (lambda d, c: (d, _edit_line(c, "N3", " · 키: ", " 키: ")), "index_keys_separator"),
    "key_without_section": (lambda d, c: (d, _edit_line(c, "N3", "`java_logic_isolation`(§3.2)", "`java_logic_isolation`")),
                            "index_key_without_section"),
    "index_section_header_removed": (lambda d, c: (d, c.replace("## 1. 절대 금지선", "## 1) 절대 금지선")),
                                     "index_section_missing"),
    "ban_table_header_changed": (lambda d, c: (d.replace("| N | 금지선 | (A) 정의처 | 강제 키 | 비고 |",
                                                         "| N | 금지선 | 정의처 | 강제 키 | 비고 |"), c), "ban_table_header"),
    "ban_table_n_format": (lambda d, c: (d.replace("| N3 | Java 로직 금지 |", "| 3 | Java 로직 금지 |"), c), "ban_table_n"),
    "ban_table_columns": (lambda d, c: (d.replace("| N9 | 실데이터 파인튜닝 금지 | §1.3 ⓔ |", "| N9 | §1.3 ⓔ |"), c),
                          "ban_table_columns"),
}


@pytest.mark.parametrize("name", sorted(FORMAT_ERRORS))
def test_unreadable_format_is_an_error_not_a_pass(name):
    forge, code = FORMAT_ERRORS[name]
    design, claude = forge(DESIGN, CLAUDE)
    with pytest.raises(BanIndexError, match=code):
        check(design, claude)


def test_description_text_before_the_anchor_is_not_checked():
    """설명 문구(→ 앞)는 일치 검사 대상이 아니다 — 키가 아닌 백틱(N4의 burp/montoya처럼)은 통과."""
    forged = _edit_line(CLAUDE, "N4", "Python 엔진에", "Python 엔진(`whatever_not_a_key`)에")
    assert check(DESIGN, forged) == []


@pytest.mark.parametrize("n,old,new", [
    ("N2", "도구가 대상 서버로", "도구(`tools_no_external_send`)가 대상 서버로"),                       # 실제 키 심기
    ("N10", "P2 범위. 단", "P2 범위. 1주차 능동 강제 아님(`no_multiagent_rag`=not_implemented→P2). 단"),  # 옛 상태 주장 복원
])
def test_manifest_key_written_in_description_is_a_format_error(n, old, new):
    """설명 문구에 실제 manifest 키를 적으면 형식 오류 — 상태 주장이 설명으로 다시 들어오는 경로를 막는다."""
    with pytest.raises(BanIndexError, match="index_key_in_description"):
        check(DESIGN, _edit_line(CLAUDE, n, old, new))


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "claude_md_sync_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_claude_md_sync.py::"
MUTATIONS = {
    "rule1_off": ('        problems += [f"ban_key_not_in_section3@{n}:{k}" for k in sorted(row.keys) if k not in section3]\n',
                  "        pass\n", [_T + "test_ban_table_key_missing_from_section3_is_caught"]),
    "rule2_line_compare_off": ("    for n in sorted(set(table) & set(index)):\n", "    for n in []:\n",
                               [_T + "test_forged_index_is_caught"]),
    "rule2_line_set_off": ("    for n in sorted(set(table) - set(index)):  # 규칙 2\n", "    for n in []:\n",
                           [_T + "test_forged_index_is_caught[line_deleted]"]),
    "rule3_b_off": ("    if missing := b_interpretation_keys(design_text) - frozenset().union(*(r.keys for r in b_rows)):\n",
                    "    if missing := frozenset():\n", [_T + "test_b_row_dropping_a_b_interpretation_key_is_caught"]),
    "rule3_codes_off": ("            if not any(key in row.keys for row in owners):\n", "            if False:\n",
                        [_T + "test_n8_dropping_the_coded_section3_key_is_caught"]),
    "description_key_check_off": ('        if set(re.findall(r"`([^`]+)`", description)) & known_keys:  # 설명 문구 속 manifest 키 표기\n',
                                  "        if False:\n", [_T + "test_manifest_key_written_in_description_is_a_format_error"]),
    "format_lenient": ("def _fail(code: str) -> None:\n    raise BanIndexError(code)\n",
                       "def _fail(code: str) -> None:\n    return None  # 변이: 형식 검사 해제(관대 파싱)\n",
                       [_T + "test_unreadable_format_is_an_error_not_a_pass", _T + "test_duplicated_index_line_is_an_error",
                        _T + "test_n5_without_the_none_marker_is_a_format_error"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_sync_rule_is_load_bearing_under_verified_mutation(tmp_path, name):
    old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", "tools/guardrails/ban_index.py", old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), "tools.guardrails.ban_index", *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
