"""정적 대조 — Pydantic 초안 계약의 제약이 LLM에 전달되는지 경로별로 판정한다. (A) §2.8, `llm_contract_conveyed`.

`python -m tools.eval.schema_gap`이 표를 출력한다. 판정 값:
- represented: 같은 제약이 전송 스키마에 키워드로 있다(서버 문법이 그 키워드를 강제하는지는 별개 — docs/inference-server.md의 탐침).
- conveyed_by_rule: 스키마에는 없고, 프롬프트의 출력 규칙 절에 그 하위 제약의 문장이 모두 있다.
- excluded: 정당한 제외 — `EXCLUSION_BASIS`에 근거가 있는 필드만(초안 금지: range, advisory_signals).
- missing: 어느 수단으로도 전달되지 않는다(근거 없는 제외 포함).
- not_expressible: 검증 함수인데 `SUBCONSTRAINTS`에 분해가 없다 — 새 검증기가 생기면 여기로 떨어지고 고정 테스트가 실패한다.

복합 검증기는 하위 제약 단위로 판정한다(하나가 스키마로 전달돼도 나머지를 대신하지 않는다).

게이트 검사(`gate_checks`): 게이트가 LLM 초안에 적용하는 검사(`output_gate.DRAFT_CHECKS`)마다 근거 게이트 판정과 전달 수단을
`GATE_CHECKS`에 둔다. 수단은 초안 계약 판정(contract) / 기존 Rules: 절 문장 원문(rule — 템플릿을 바꾸지 않고 등록만) /
출력 규칙(output_rule) / 항상 해석됨(always) 중 하나 이상이고, 모두 성립해야 conveyed다.
기준((A) v1.41 무효 처리 규칙): 게이트가 요구하는 조건을 우리가 준 정보만으로 모델이 알 수 있는가.

범위(정직 표기): 우리 쪽 정의(스키마·프롬프트)에 전달 수단이 있는지만 본다. 모델이 지키는지는 게이트가 판정하고,
llama.cpp 문법이 어떤 키워드를 건너뛰는지는 이 도구가 알 수 없다. 거부 사유 코드는 전부 `DRAFT_CHECKS`에 대응되지만
(`output_gate.CHECKS_OF_REASON`), 같은 사유 코드 아래의 새 해석 조건은 기계로 못 잡는다 — 게이트를 고칠 때 함께 고친다.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Annotated, Any, Final, Literal, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from sentinel.common_types import POINTER_PATTERN
from sentinel.output_schema import AnalysisDraft
from sentinel.pipeline.llm_prompt import LLM_DROPPED_FIELDS, OUTPUT_RULES, RULES_HEADING, SYSTEM_PROMPT, TRANSMISSION_SCHEMA

KEYWORD_OF: Final = {"uuid": "format", "min_length": "minItems", "ge": "minimum", "extra_forbid": "additionalProperties",
                     "literal": "enum/const", "pattern": "pattern"}
# 검증 함수 → (하위 제약 ID, 스키마 판정 — None이면 스키마로 전달하지 않음). ID는 llm_prompt.OUTPUT_RULES의 키와 같다
SUBCONSTRAINTS: Final = {
    "_check_json_pointer": (("json_pointer.syntax", lambda node: node.get("pattern") == POINTER_PATTERN),  # RFC 6901 문법
                            ("json_pointer.no_dash_token", None),  # pattern에 넣지 않는다: 위반이 HTTP 500(환경 실패)으로 잘못 분류된다
                            ("json_pointer.one_node", None)),  # 데이터에 따라 달라짐 — 게이트 해석(evidence_pointer_resolves)
}
EXCLUSION_BASIS: Final = {
    "range": "(A) §2.8 LLM 초안 스키마에는 Locator의 range가 없다(뷰 오프셋 ≠ 원본 오프셋)",
    "advisory_signals": "(A) §2.8 LLM 초안은 advisory_signals를 만들지 않는다(v1 — 전송 스키마에서 빈 배열 고정)",
}


EXISTING_RULES_HEADING: Final = "Rules:"
# 기존 Rules: 절 문장 원문(템플릿 불변 — 등록만)
T_REF: Final = "evidence.transaction_ref copies transaction_id exactly."
T_POINTER: Final = ("evidence.pointer names a place that exists in the data: resp_status, req_line, req_header, resp_header, req_param, "
                    "req_body or resp_body. Header and parameter names are copied exactly and occurrence starts at 0.")
T_OBSERVATION: Final = ("evidence.observation states what is there. Masked values stay as the labels you see. "
                        "Never invent a value, token, key or password.")
CONTRACT: Final = ("contract",)
# 게이트 검사 → (근거 게이트 판정 output_gate.<심볼>, 전달 수단들)
GATE_CHECKS: Final = {
    "draft_schema": ("_checked_draft", (CONTRACT,)),
    "category_closed": ("_checked_draft", (CONTRACT,)),
    "evidence_min_one": ("_checked_draft", (CONTRACT,)),
    "llm_no_range": ("_has_range", (CONTRACT,)),  # 전송 스키마에 range 없음 + 추가 필드 금지
    "transaction_ref_in_analyzed": ("_refs_outside", (("rule", T_REF),)),  # 뷰에 transaction_id가 있다
    "locus_names": ("_resolves", (("rule", T_POINTER), ("output_rule", "gate.locus_names"))),
    "status_always": ("_resolves", (("always", "StatusLocator는 항상 해석된다"),)),
    "req_line_part": ("_resolves", (CONTRACT,)),  # part enum, range 없음 → method·path는 항상 있다
    "header_name_case_insensitive": ("_resolves", (("rule", T_POINTER),)),  # 정확히 복사 ⊂ 대소문자 무시 비교
    "header_occurrence_by_name": ("_resolves", (("output_rule", "gate.occurrence"),)),
    "param_location_and_name_exact": ("_resolves", (("rule", T_POINTER),)),  # location은 스키마 enum + 뷰의 location 키
    "param_occurrence_by_location_and_name": ("_resolves", (("output_rule", "gate.occurrence"),)),
    "body_needs_content": ("_body_resolves", (("rule", T_POINTER),)),  # content가 없으면 뷰에 content 키도 없다
    "body_json_needs_json_content": ("_body_resolves", (("output_rule", "gate.body_kind"),)),
    "body_json_needs_untruncated": ("_body_resolves", (("output_rule", "gate.body_kind"),)),
    "body_json_one_node": ("_body_resolves", (CONTRACT,)),  # json_pointer.one_node 하위 제약(출력 규칙)
    "literal_isolation": ("_isolated", (("rule", T_OBSERVATION),)),
}


def _constraints(field: FieldInfo, annotation: Any, model: type[BaseModel], name: str) -> list[str]:
    found = []
    if annotation is uuid.UUID:
        found.append("uuid")
    if get_origin(annotation) is Literal:
        found.append("literal")
    for meta in field.metadata:
        kind = type(meta).__name__
        if kind == "MinLen":
            found.append("min_length")
        elif kind == "Ge":
            found.append("ge")
        elif kind in ("AfterValidator", "BeforeValidator", "PlainValidator", "WrapValidator"):
            found.append(f"validator:{getattr(meta.func, '__name__', 'anonymous')}")
        elif kind == "_PydanticGeneralMetadata" and getattr(meta, "pattern", None):
            found.append("pattern")
    decorators = model.__pydantic_decorators__
    found += [f"validator:{d.func.__name__}" for d in decorators.field_validators.values() if name in d.info.fields]
    return found


def _schema_has(node: dict[str, Any], constraint: str) -> bool:
    if constraint.startswith("validator:"):
        return False
    if constraint == "pattern":
        return "pattern" in node
    if constraint == "literal":
        return "enum" in node or "const" in node
    keyword = KEYWORD_OF[constraint]
    if constraint == "uuid":
        return node.get("format") == "uuid"
    if constraint == "extra_forbid":
        return node.get("additionalProperties") is False
    return keyword in node


def _branches(node: dict[str, Any]) -> list[dict[str, Any]]:
    return node.get("oneOf") or node.get("anyOf") or [node]


def _variant(node: dict[str, Any], discriminator: str, value: str) -> dict[str, Any] | None:
    for branch in _branches(node):
        spec = branch.get("properties", {}).get(discriminator, {})
        if spec.get("const") == value or value in spec.get("enum", ()):
            return branch
    return None


def _models_in(annotation: Any) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    if get_origin(annotation) is Literal:
        return []
    return [m for arg in get_args(annotation) for m in _models_in(arg)]


def _array_item(node: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if node is None else node.get("items", node)


def _rule_lines(prompt: str) -> set[str]:
    """출력 규칙 절(제목 다음부터 시스템 지시문 끝까지)의 규칙 줄. 절 밖의 같은 문장은 세지 않는다."""
    if RULES_HEADING not in prompt:
        return set()
    return {line[2:] for line in prompt.split(RULES_HEADING, 1)[1].splitlines() if line.startswith("- ")}


def _excluded(path: str, name: str, schema: str) -> dict[str, str]:
    if name not in EXCLUSION_BASIS:
        return {"path": path, "pydantic": "field", "schema": schema, "verdict": "missing", "basis": "근거 없는 제외"}
    return {"path": path, "pydantic": "field", "schema": schema, "verdict": "excluded", "basis": EXCLUSION_BASIS[name]}


def gaps(root: type[BaseModel] = AnalysisDraft, schema: dict[str, Any] = TRANSMISSION_SCHEMA, prompt: str = SYSTEM_PROMPT,
         rules: dict[str, tuple[str, ...]] = OUTPUT_RULES) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    lines = _rule_lines(prompt)

    def judge(path: str, constraint: str, node: dict[str, Any] | None) -> None:
        func = constraint.removeprefix("validator:")
        if not constraint.startswith("validator:") or func not in SUBCONSTRAINTS:
            rows.append(_row(path, constraint, node))
            return
        for sub_id, in_schema in SUBCONSTRAINTS[func]:
            rows.append(_sub_row(path, func, sub_id, in_schema, node, lines, rules))

    def visit(model: type[BaseModel], node: dict[str, Any] | None, path: str) -> None:
        if model.model_config.get("extra") == "forbid":
            rows.append(_row(path or "(root)", "extra_forbid", node))
        for d in model.__pydantic_decorators__.model_validators.values():
            judge(path or "(root)", f"validator:{d.func.__name__}", node)
        for name, field in model.model_fields.items():
            here = f"{path}.{name}" if path else name
            child = None if node is None else node.get("properties", {}).get(name)
            if name in LLM_DROPPED_FIELDS:
                rows.append(_excluded(here, name, "-"))
                continue
            annotation = field.annotation
            base = get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation
            for constraint in _constraints(field, base, model, name):
                judge(here, constraint, child)
            is_list = get_origin(base) in (list, tuple)
            if child is not None and child.get("maxItems") == 0:
                rows.append(_excluded(here, name, "maxItems 0"))
                continue
            target = _array_item(child) if is_list else child
            members = _models_in(base)
            if field.discriminator:
                for member in members:
                    for value in get_args(member.model_fields[field.discriminator].annotation):
                        branch = None if target is None else _variant(target, field.discriminator, value)
                        visit(member, branch, f"{here}{{{field.discriminator}={value}}}")
            else:
                for member in members:
                    visit(member, target, here + ("[]" if is_list else ""))

    visit(root, schema, "")
    return rows


def _row(path: str, constraint: str, node: dict[str, Any] | None) -> dict[str, str]:
    if constraint.startswith("validator:"):
        return {"path": path, "pydantic": constraint, "schema": "-", "verdict": "not_expressible"}
    present = node is not None and _schema_has(node, constraint)
    keyword = KEYWORD_OF[constraint]
    return {"path": path, "pydantic": constraint, "schema": keyword if present else "-", "verdict": "represented" if present else "missing"}


def _sub_row(path: str, func: str, sub_id: str, in_schema: Callable[[dict[str, Any]], bool] | None, node: dict[str, Any] | None,
             lines: set[str], rules: dict[str, tuple[str, ...]]) -> dict[str, str]:
    label = f"validator:{func}/{sub_id}"
    if in_schema is not None and node is not None and in_schema(node):
        return {"path": path, "pydantic": label, "schema": "keyword", "verdict": "represented"}
    sentences = rules.get(sub_id, ())
    if sentences and all(s in lines for s in sentences):
        return {"path": path, "pydantic": label, "schema": "output rule", "verdict": "conveyed_by_rule"}
    return {"path": path, "pydantic": label, "schema": "-", "verdict": "missing"}


VERDICTS: Final = ("represented", "conveyed_by_rule", "excluded", "missing", "not_expressible")
CONVEYED: Final = frozenset({"represented", "conveyed_by_rule", "excluded"})


def _existing_rule_lines(prompt: str) -> set[str]:
    """기존 Rules: 절(제목 다음부터 출력 규칙 제목 앞까지)의 규칙 줄."""
    marker = "\n" + EXISTING_RULES_HEADING + "\n"
    if marker not in prompt:
        return set()
    section = prompt.split(marker, 1)[1].split(RULES_HEADING, 1)[0]
    return {line[2:] for line in section.splitlines() if line.startswith("- ")}


def gate_checks(prompt: str = SYSTEM_PROMPT, rules: dict[str, tuple[str, ...]] = OUTPUT_RULES,
                checks: dict[str, tuple[str, tuple[tuple[str, ...], ...]]] = GATE_CHECKS) -> list[dict[str, str]]:
    """게이트 검사마다 (근거 판정, 전달 수단, 판정). 수단이 모두 성립해야 conveyed."""
    contract_ok = all(r["verdict"] in CONVEYED for r in gaps(prompt=prompt, rules=rules))
    existing, output = _existing_rule_lines(prompt), _rule_lines(prompt)

    def holds(means: tuple[str, ...]) -> bool:
        kind = means[0]
        if kind == "contract":
            return contract_ok
        if kind == "rule":
            return means[1] in existing
        if kind == "output_rule":
            sentences = rules.get(means[1], ())
            return bool(sentences) and all(s in output for s in sentences)
        return kind == "always"

    return [{"check": check, "gate": f"output_gate.{symbol}", "means": " + ".join(m[0] if m[0] != "output_rule" else m[1] for m in means),
             "verdict": "conveyed" if means and all(holds(m) for m in means) else "missing"}
            for check, (symbol, means) in checks.items()]


def main() -> int:
    rows = gaps()
    print("| 경로 | Pydantic 제약 | 전송 수단 | 판정 | 제외 근거 |")
    print("|---|---|---|---|---|")
    for row in rows:
        print(f"| {row['path']} | {row['pydantic']} | {row['schema']} | {row['verdict']} | {row.get('basis', '')} |")
    print(json.dumps({v: sum(1 for r in rows if r["verdict"] == v) for v in VERDICTS}))
    print()
    print("| 게이트 검사 | 근거 판정 | 전달 수단 | 판정 |")
    print("|---|---|---|---|")
    for row in gate_checks():
        print(f"| {row['check']} | {row['gate']} | {row['means']} | {row['verdict']} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
