"""(A) 정본 `docs/design-decision.md` §3 매핑표 파서.

§3.1~§3.5의 표를 기계 판독해 규칙 행 목록으로 돌려준다. 정본 형식이 예상과 다르면
추측해 채우지 않고 SpecError로 멈춘다(fail-closed).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# (A) 목표층위 표기 → (B) W1-00 목표층위 어휘.
# 복합 표기(예: "validator+테스트")는 (A) §3 머리말 "목표 층위 = 주된 강제 지점"에 따라 첫 항목으로 정규화한다.
# 여기 없는 표기가 (A)에 나타나면 파생을 거부한다 — 사람이 매핑을 결정해야 한다.
LAYER_MAP: dict[str, str] = {
    "타입 레벨": "타입",
    "스키마": "스키마·validator",
    "스키마/validator": "스키마·validator",
    "validator": "스키마·validator",
    "validator+테스트": "스키마·validator",
    "테스트": "테스트",
    "테스트+설정": "테스트",
    "아키텍처 테스트": "아키텍처테스트",
    "CI(pre-commit)": "CI게이트",
    "CI(branch protection)": "CI게이트",
    "파생(하위 4키 AND)": "파생",
    "—": "외부",
}

TABLE_SECTIONS = ("3.1", "3.2", "3.3", "3.4", "3.5")
TABLE_HEADER = ["규칙", "목표층위", "1주차 상태", "manifest 키"]

_SECTION3_RE = re.compile(r"^## 3\. .*매핑표 (v[\d.]+)")
_SUBSECTION_RE = re.compile(r"^### (3\.\d+)\b")
_STATE_PLAIN_RE = re.compile(r"^(enforced|unverifiable|disabled)(?:\((.+)\))?$")
_STATE_NOT_IMPL_RE = re.compile(r"^not_implemented\s*→\s*(.+)$")
_STATE_DERIVED_RE = re.compile(r"^derived\s*\(→\s*(.+)\)$")
_KEY_RE = re.compile(r"^`([a-z0-9_]+)`$")


class SpecError(ValueError):
    """정본 (A) §3을 기계 판독할 수 없음."""


@dataclass(frozen=True)
class SpecRow:
    key: str
    section: str
    rule: str
    layer: str
    state: str  # enforced | not_implemented | unverifiable | disabled | derived
    target: str | None  # not_implemented·derived의 목표 시점(→N주차)
    note: str | None  # enforced(...)·unverifiable(...)의 범위 한정
    derived_from: tuple[str, ...]


@dataclass(frozen=True)
class Spec:
    version: str
    rows: tuple[SpecRow, ...]

    def by_key(self) -> dict[str, SpecRow]:
        return {r.key: r for r in self.rows}


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _parse_state(raw: str, key: str) -> tuple[str, str | None, str | None]:
    raw = raw.replace("†", "").strip()
    if m := _STATE_PLAIN_RE.match(raw):
        return m.group(1), None, m.group(2)
    if m := _STATE_NOT_IMPL_RE.match(raw):
        return "not_implemented", m.group(1).strip(), None
    if m := _STATE_DERIVED_RE.match(raw):
        return "derived", m.group(1).strip(), None
    if raw == "derived":  # 목표 없는 derived — 자기 목표가 없는 롤업. not_implemented는 여전히 목표 필수
        return "derived", None, None
    raise SpecError(f"{key}: 해석할 수 없는 1주차 상태 표기 {raw!r}")


def _derived_children(text: str, key: str) -> tuple[str, ...]:
    # 각주 † 형식: > **† `key` (...):** `a ∧ b ∧ c`.
    for line in text.splitlines():
        if line.startswith("> **†") and f"`{key}`" in line:
            for expr in re.findall(r"`([^`]+)`", line):
                if "∧" in expr:
                    return tuple(part.strip() for part in expr.split("∧"))
    raise SpecError(f"{key}: derived인데 각주 †에서 하위 키 목록(∧)을 찾을 수 없음")


def parse_spec(text: str) -> Spec:
    version: str | None = None
    section: str | None = None
    rows: list[SpecRow] = []
    seen_sections: set[str] = set()
    pending_derived: list[tuple[int, str]] = []

    for line in text.splitlines():
        if m := _SECTION3_RE.match(line):
            version = m.group(1)
            continue
        if line.startswith("## ") and version is not None:
            break  # §3 끝
        if m := _SUBSECTION_RE.match(line):
            section = m.group(1) if m.group(1) in TABLE_SECTIONS else None
            continue
        if section is None or not line.startswith("|"):
            continue
        cells = _cells(line)
        if cells == TABLE_HEADER:
            seen_sections.add(section)
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue  # 구분선
        if len(cells) != 4:
            raise SpecError(f"§{section}: 열 개수가 4가 아닌 행 {line!r}")
        rule, layer_raw, state_raw, key_raw = cells
        km = _KEY_RE.match(key_raw)
        if not km:
            raise SpecError(f"§{section}: manifest 키 표기 오류 {key_raw!r}")
        key = km.group(1)
        if layer_raw not in LAYER_MAP:
            raise SpecError(f"{key}: 매핑되지 않은 목표층위 {layer_raw!r} — LAYER_MAP 결정 필요")
        state, target, note = _parse_state(state_raw, key)
        if state == "derived":
            pending_derived.append((len(rows), key))
        rows.append(SpecRow(key, section, rule, LAYER_MAP[layer_raw], state, target, note, ()))

    if version is None:
        raise SpecError("§3 매핑표 머리(## 3. ... 매핑표 vX.Y)를 찾을 수 없음")
    missing = set(TABLE_SECTIONS) - seen_sections
    if missing:
        raise SpecError(f"표를 찾을 수 없는 절: {sorted(missing)}")
    for idx, key in pending_derived:
        r = rows[idx]
        rows[idx] = SpecRow(r.key, r.section, r.rule, r.layer, r.state, r.target, r.note,
                            _derived_children(text, key))
    keys = [r.key for r in rows]
    dups = sorted({k for k in keys if keys.count(k) > 1})
    if dups:
        raise SpecError(f"§3에 중복 manifest 키: {dups}")
    return Spec(version, tuple(rows))


def load_spec(path: Path) -> Spec:
    return parse_spec(path.read_text(encoding="utf-8"))
