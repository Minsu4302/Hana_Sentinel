"""`guardrails.yaml` — 가드레일 기계 판독 SSOT의 로드·검증·동기화.

구조는 (B) W1-00 6필드 스키마로 고정한다. 임의 필드 추가·누락은 거부.
`guardrails.yaml`은 손으로 짜지 않는다: `sync`가 (A) §3에서 파생해 쓰고,
사람(구현자)이 바꾸는 것은 (A)가 enforced를 목표로 둔 키의 '실제 승격'(state=enforced +
검증 테스트 식별자)뿐이다. 그 외 모든 값은 (A)와 다르면 검증이 거부한다.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import yaml

from tools.guardrails.spec import LAYER_MAP, Spec, SpecRow

# (B) W1-00 6필드: 가드레일 ID / 설명 / 목표층위 / 1주차 상태 / 검증 테스트 식별자 / manifest 키
FIELDS = ("id", "description", "target_layer", "week1_status", "verification_tests", "manifest_key")
# (A) §3 머리말: manifest 상태 4종 + 파생 상태(derived)
STATES = ("enforced", "not_implemented", "disabled", "unverifiable", "derived")
STATUS_KEYS = {"state", "target", "note", "derived_from"}
LAYERS = tuple(dict.fromkeys(LAYER_MAP.values()))
# (A)가 enforced를 1주차 목표로 둔 키가 아직 증명되지 않았을 때의 목표 시점
WEEK1_TARGET = "1주차"
SCHEMA_VERSION = "1"

Entry = dict[str, Any]


class RegistryError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("guardrails.yaml 검증 실패:\n" + "\n".join(f"  - {e}" for e in errors))


def load_registry(path: Path) -> list[Entry]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
        raise RegistryError([f"최상위는 schema_version={SCHEMA_VERSION!r}를 가진 매핑이어야 함"])
    entries = doc.get("guardrails")
    if not isinstance(entries, list):
        raise RegistryError(["guardrails 키는 목록이어야 함"])
    return entries


def expected_status(row: SpecRow, current: Any) -> dict[str, Any]:
    """(A) 행과 현재 상태로부터 정직한 상태값을 정한다. 승격은 (A)가 enforced를 목표로 둔 키만 가능."""
    if row.state == "enforced":
        promoted = isinstance(current, dict) and current.get("state") == "enforced"
        status: dict[str, Any] = {"state": "enforced"} if promoted else {
            "state": "not_implemented", "target": WEEK1_TARGET}
    elif row.state == "derived":
        status = {"state": "derived", "target": row.target, "derived_from": list(row.derived_from)}
    else:
        status = {"state": row.state}
        if row.target:
            status["target"] = row.target
    if row.note:
        status["note"] = row.note
    return status


def sync(spec: Spec, current: list[Entry]) -> list[Entry]:
    """(A) §3 → guardrails.yaml 파생. 현재 파일에서 보존하는 것은 enforced 승격(상태+테스트)뿐."""
    by_id = {e.get("id"): e for e in current if isinstance(e, dict)}
    out: list[Entry] = []
    for row in spec.rows:
        old = by_id.get(row.key, {})
        status = expected_status(row, old.get("week1_status"))
        tests = list(old.get("verification_tests") or []) if status["state"] == "enforced" else []
        out.append({
            "id": row.key,
            "description": row.rule,
            "target_layer": row.layer,
            "week1_status": status,
            "verification_tests": tests,
            "manifest_key": row.key,
        })
    return out


def resolve_test(root: Path, node_id: str) -> bool:
    """pytest 노드 ID가 정적으로 실재하는지(파일 + 함수/클래스 메서드). 수집·통과는 여기서 확인하지 않음."""
    parts = node_id.split("[", 1)[0].split("::")
    if len(parts) not in (2, 3) or not parts[0].endswith(".py"):
        return False
    path = root / parts[0]
    if not path.is_file():
        return False
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scope: list[ast.stmt] = tree.body
    for name in parts[1:-1]:
        cls = next((n for n in scope if isinstance(n, ast.ClassDef) and n.name == name), None)
        if cls is None:
            return False
        scope = cls.body
    return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == parts[-1]
               and n.name.startswith("test") for n in scope)


def validate(entries: list[Entry], spec: Spec, root: Path) -> None:
    """구조 정합 + (A) 일치 검증. 하나라도 어긋나면 전부 모아 RegistryError(fail-closed)."""
    errors: list[str] = []
    ids: list[str] = []
    for i, e in enumerate(entries):
        where = f"guardrails[{i}]"
        if not isinstance(e, dict):
            errors.append(f"{where}: 매핑이 아님")
            continue
        missing = [f for f in FIELDS if f not in e]
        extra = sorted(set(e) - set(FIELDS))
        if missing:
            errors.append(f"{where}: 필수 필드 누락 {missing}")
        if extra:
            errors.append(f"{where}: 스키마 밖 필드 {extra}")
        if missing:
            continue
        gid = e["id"]
        where = f"{gid}"
        ids.append(gid)
        if not isinstance(gid, str) or not gid:
            errors.append(f"{where}: id는 비어 있지 않은 문자열이어야 함")
        if e["manifest_key"] != gid:
            errors.append(f"{where}: manifest_key({e['manifest_key']!r}) ≠ id")
        if not isinstance(e["description"], str) or not e["description"]:
            errors.append(f"{where}: description이 비어 있음")
        if e["target_layer"] not in LAYERS:
            errors.append(f"{where}: 미지 target_layer {e['target_layer']!r}")
        status, tests = e["week1_status"], e["verification_tests"]
        if not isinstance(tests, list) or not all(isinstance(t, str) for t in tests):
            errors.append(f"{where}: verification_tests는 문자열 목록이어야 함")
            tests = []
        if not isinstance(status, dict) or set(status) - STATUS_KEYS:
            errors.append(f"{where}: week1_status 형식 오류 {status!r}")
            continue
        state = status.get("state")
        if state not in STATES:
            errors.append(f"{where}: 미지 status {state!r} (허용: {', '.join(STATES)})")
            continue
        if state == "enforced":
            if not tests:
                errors.append(f"{where}: enforced인데 검증 테스트 식별자 없음 — 거짓 enforced 선언")
            for t in tests:
                if not resolve_test(root, t):
                    errors.append(f"{where}: 검증 테스트 {t!r}가 실재하지 않음 — 거짓 enforced 선언")
        elif tests:
            errors.append(f"{where}: {state}인데 검증 테스트 식별자가 있음(enforced만 허용)")
        if state == "not_implemented" and not status.get("target"):
            errors.append(f"{where}: not_implemented인데 목표 시점(target) 없음")

    dups = sorted({g for g in ids if ids.count(g) > 1})
    if dups:
        errors.append(f"중복 가드레일 ID: {dups}")

    # (A) §3 일치 — 뷰 동기화 ① guardrails.yaml ↔ (A) §3 매핑표
    spec_rows = spec.by_key()
    known = {e["id"]: e for e in entries if isinstance(e, dict) and "id" in e}
    for key in spec_rows.keys() - known.keys():
        errors.append(f"{key}: (A) §3에 있으나 guardrails.yaml에 없음")
    for key in known.keys() - spec_rows.keys():
        errors.append(f"{key}: (A) §3에 없는 키(임의 추가)")
    for key, e in known.items():
        row = spec_rows.get(key)
        if row is None or not all(f in e for f in FIELDS):
            continue
        if e["description"] != row.rule:
            errors.append(f"{key}: description이 (A) §{row.section}와 다름")
        if e["target_layer"] != row.layer:
            errors.append(f"{key}: target_layer {e['target_layer']!r} ≠ (A) 파생값 {row.layer!r}")
        status = e["week1_status"]
        if not isinstance(status, dict) or status.get("state") not in STATES:
            continue
        if status["state"] == "derived":
            for child in status.get("derived_from") or []:
                c = known.get(child)
                if c is None or child == key:
                    errors.append(f"{key}: derived 하위 키 {child!r}가 레지스트리에 없음")
                elif isinstance(c.get("week1_status"), dict) and c["week1_status"].get("state") == "derived":
                    errors.append(f"{key}: derived 하위 키 {child!r}가 다시 derived(중첩 롤업 금지)")
            if not status.get("derived_from"):
                errors.append(f"{key}: derived인데 하위 키 목록 없음")
        if status["state"] == "enforced" and row.state != "enforced":
            shown = row.state + (f"(→{row.target})" if row.target else "")
            errors.append(f"{key}: (A)가 {shown}인 키를 enforced로 주장 — 참칭")
        elif status != expected_status(row, status):
            errors.append(f"{key}: week1_status {status!r} ≠ (A) 파생값 {expected_status(row, status)!r}")

    if errors:
        raise RegistryError(errors)


def _q(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)  # JSON 문자열 = 유효한 YAML 큰따옴표 스칼라


def render_yaml(entries: list[Entry], spec: Spec) -> str:
    lines = [
        "# guardrails.yaml — 가드레일 기계 판독 SSOT (생성물: `make guardrails-sync`).",
        f"# 원천: (A) docs/design-decision.md §3 강제 매핑표 {spec.version}. 값이 다르면 (A)가 정본이다.",
        "# 손으로 바꿔도 되는 것: (A)가 enforced를 목표로 둔 키의 실제 승격(state: enforced + verification_tests)뿐.",
        "# enforced는 실제 통과 테스트가 있는 것만. 목표 주차 ≠ 현재 상태.",
        f"schema_version: {_q(SCHEMA_VERSION)}",
        f"derived_from: {_q(f'docs/design-decision.md §3 매핑표 {spec.version}')}",
        "guardrails:",
    ]
    for e in entries:
        s = e["week1_status"]
        lines += [
            f"  - id: {e['id']}",
            f"    description: {_q(e['description'])}",
            f"    target_layer: {_q(e['target_layer'])}",
            "    week1_status:",
            f"      state: {s['state']}",
        ]
        if "target" in s:
            lines.append(f"      target: {_q(s['target'])}")
        if "note" in s:
            lines.append(f"      note: {_q(s['note'])}")
        if "derived_from" in s:
            lines.append("      derived_from: [" + ", ".join(s["derived_from"]) + "]")
        if e["verification_tests"]:
            lines.append("    verification_tests:")
            lines += [f"      - {_q(t)}" for t in e["verification_tests"]]
        else:
            lines.append("    verification_tests: []")
        lines.append(f"    manifest_key: {e['manifest_key']}")
    return "\n".join(lines) + "\n"
