"""`claude_md_sync_check` — CLAUDE.md 금지선 색인 ↔ (A) §1.4 금지선 강제 매핑. (A) §1.4, §3.1.

검사 규칙:
  1) §1.4의 모든 강제 키가 §3 표에 실재.
  2) CLAUDE.md §1의 N줄 집합 = §1.4 N행 집합(누락·중복·여분 없음). 줄마다 정의처 집합·키 집합이 §1.4와 같고,
     키 옆 소절 = 그 키의 실제 §3.x. 키 없는 행(N5)은 색인에도 '키: 없음' 명시가 있어야 한다.
  3) (A) 내부 교차: §1.4 ⓑ행 ⊇ ⓑ 해석의 강제 매핑 키 / §3 규칙 칸에 금지선 코드가 적힌 행의 키 ∈ 그 코드를 정의처로
     갖는 §1.4 행.
범위(정직 표기): §1.4 자체의 완전성(빠진 강제 키가 없는가)은 검사하지 않는다 — 리뷰 몫. 줄의 설명 문구(`→` 앞)는 대상이
아니다.

형식(fail-closed — 읽을 수 없으면 통과가 아니라 BanIndexError):
  CLAUDE.md §1의 `- **N<번호>` 줄 꼬리 = ` → 정의처: <, 목록> · 키: <없음… | `키`(§3.x), …>`. 앵커는 정확히 1개,
  `· 키:`는 정확히 1개, 줄 안의 정의처·키 중복 금지, 키마다 바로 뒤 `(§3.x)`, 마지막 키 뒤 나머지(재론 괄호 등 평문)는
  무시하되 백틱 키가 있으면 오류. §1 머리를 못 찾거나 N줄을 0개 읽으면 오류. §1.4 표 머리·열 개수·N번호 형식 오류도 오류.
§3 표는 기존 `spec` 파서(`load_spec().by_key()`)를 그대로 쓴다 — 이 모듈은 §3을 따로 읽지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from tools.guardrails import REPO_ROOT
from tools.guardrails.spec import parse_spec

DESIGN_DOC = REPO_ROOT / "docs" / "design-decision.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"

BAN_TABLE_HEADER = ["N", "금지선", "(A) 정의처", "강제 키", "비고"]
CODES = "ⓐⓑⓒⓓⓔⓕⓖ"
_N_RE = re.compile(r"^N([1-9][0-9]*)$")
_DEF_RE = re.compile(rf"^§[0-9]+(\.[0-9]+)?( [{CODES}])?$")
_KEY_CELL_RE = re.compile(r"^`([a-z0-9_]+)`$")
_INDEX_LINE_RE = re.compile(r"^- \*\*(N[0-9]+)[ *]")
_ANCHOR = " → 정의처: "
_KEYS_SEP = " · 키: "
_KEY_WITH_SECTION_RE = re.compile(r"`([a-z0-9_]+)`\(§(3\.[0-9]+)\)")
_B_INTERP_MAPPING = "> - 강제 매핑:"


class BanIndexError(ValueError):
    """형식 오류 — 읽을 수 없으면 통과가 아니다."""


def _fail(code: str) -> None:
    raise BanIndexError(code)


@dataclass(frozen=True)
class BanRow:
    definitions: frozenset[str]
    keys: frozenset[str]


@dataclass(frozen=True)
class IndexLine:
    definitions: frozenset[str]
    keys: dict[str, str]  # 키 → 표기된 소절(3.x)
    no_keys: bool


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _unique(items: list[str], code: str) -> frozenset[str]:
    if len(set(items)) != len(items):
        _fail(code)
    return frozenset(items)


def parse_ban_table(design_text: str) -> dict[str, BanRow]:
    lines = design_text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("### 1.4 ")), None)
    if start is None:
        _fail("ban_table_section_missing")
    rows: dict[str, BanRow] = {}
    header_seen = False
    for line in lines[start + 1:]:
        if line.startswith(("## ", "### ", "---")):
            break
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if not header_seen:
            if cells != BAN_TABLE_HEADER:
                _fail("ban_table_header")
            header_seen = True
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if len(cells) != len(BAN_TABLE_HEADER):
            _fail("ban_table_columns")
        n, _ban, defs_raw, keys_raw, _note = cells
        if not _N_RE.match(n) or n in rows:
            _fail("ban_table_n")
        defs = [d.strip() for d in defs_raw.split(",")]
        if not all(_DEF_RE.match(d) for d in defs):
            _fail("ban_table_definition")
        if keys_raw == "(없음)":
            keys: list[str] = []
        else:
            matches = [_KEY_CELL_RE.match(k.strip()) for k in keys_raw.split(",")]
            if not all(matches):
                _fail("ban_table_key")
            keys = [m.group(1) for m in matches]
        rows[n] = BanRow(_unique(defs, "ban_table_duplicate_definition"), _unique(keys, "ban_table_duplicate_key"))
    if not rows:
        _fail("ban_table_empty")
    return rows


def b_interpretation_keys(design_text: str) -> frozenset[str]:
    lines = [line for line in design_text.splitlines() if line.startswith(_B_INTERP_MAPPING)]
    if len(lines) != 1:
        _fail("b_interpretation_mapping_missing")
    return frozenset(re.findall(r"`([a-z0-9_]+)`", lines[0]))


def parse_index(claude_text: str) -> dict[str, IndexLine]:
    lines = claude_text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("## 1. ")), None)
    if start is None:
        _fail("index_section_missing")
    entries: dict[str, IndexLine] = {}
    duplicates: list[str] = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        m = _INDEX_LINE_RE.match(line)
        if not m:
            continue
        n = m.group(1)
        if line.count(_ANCHOR) != 1:
            _fail("index_anchor")
        tail = line.split(_ANCHOR, 1)[1]
        if tail.count(_KEYS_SEP) != 1:
            _fail("index_keys_separator")
        defs_raw, keys_raw = tail.split(_KEYS_SEP)
        defs = [d.strip() for d in defs_raw.split(",")]
        if not all(_DEF_RE.match(d) for d in defs):
            _fail("index_definition")
        definitions = _unique(defs, "index_duplicate_definition")
        if keys_raw.startswith("없음"):
            if "`" in keys_raw:
                _fail("index_key_after_none")
            parsed = IndexLine(definitions, {}, True)
        else:
            keys: dict[str, str] = {}
            pos = 0
            while True:
                km = _KEY_WITH_SECTION_RE.match(keys_raw, pos)
                if not km:
                    _fail("index_key_without_section")
                if km.group(1) in keys:
                    _fail("index_duplicate_key")
                keys[km.group(1)] = km.group(2)
                pos = km.end()
                if keys_raw.startswith(", `", pos):
                    pos += 2
                    continue
                break
            if "`" in keys_raw[pos:]:  # 나머지(재론 괄호 등)는 평문만
                _fail("index_key_in_remainder")
            parsed = IndexLine(definitions, keys, False)
        if n in entries:
            duplicates.append(n)
        entries[n] = parsed
    if not entries:
        _fail("index_empty")
    if duplicates:
        _fail("index_duplicate_n")
    return entries


def check(design_text: str, claude_text: str) -> list[str]:
    """위반(사유 코드@위치). 형식 오류는 BanIndexError."""
    table = parse_ban_table(design_text)
    index = parse_index(claude_text)
    section3 = parse_spec(design_text).by_key()
    problems: list[str] = []

    for n, row in table.items():  # 규칙 1
        problems += [f"ban_key_not_in_section3@{n}:{k}" for k in sorted(row.keys) if k not in section3]

    for n in sorted(set(table) - set(index)):  # 규칙 2
        problems.append(f"index_missing_line@{n}")
    for n in sorted(set(index) - set(table)):
        problems.append(f"index_extra_line@{n}")
    for n in sorted(set(table) & set(index)):
        row, line = table[n], index[n]
        if line.definitions != row.definitions:
            problems.append(f"index_definitions_differ@{n}")
        if frozenset(line.keys) != row.keys:
            problems.append(f"index_keys_differ@{n}")
        if line.no_keys != (not row.keys):
            problems.append(f"index_no_keys_marker@{n}")
        for key, shown in sorted(line.keys.items()):
            if key in section3 and section3[key].section != shown:
                problems.append(f"index_key_section_differs@{n}:{key}")

    b_rows = [row for row in table.values() if any(d.endswith(" ⓑ") for d in row.definitions)]  # 규칙 3
    if missing := b_interpretation_keys(design_text) - frozenset().union(*(r.keys for r in b_rows)):
        problems += [f"b_row_misses_b_interpretation_key:{k}" for k in sorted(missing)]
    for key, spec_row in sorted(section3.items()):
        for code in sorted(set(spec_row.rule) & set(CODES)):
            owners = [row for row in table.values() if f"§1.3 {code}" in row.definitions]
            if not any(key in row.keys for row in owners):
                problems.append(f"coded_section3_key_not_in_ban_row:{key}({code})")
    return problems


def check_repo(design: Path = DESIGN_DOC, claude: Path = CLAUDE_MD) -> list[str]:
    return check(design.read_text(encoding="utf-8"), claude.read_text(encoding="utf-8"))
