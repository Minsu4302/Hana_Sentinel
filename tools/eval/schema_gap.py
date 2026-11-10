"""정적 대조 — Pydantic 초안 계약의 제약과 전송 스키마(평탄화본)를 경로별로 맞대 본다. (A) §2.8, 선별 거부 원인 진단.

`python -m tools.eval.schema_gap`이 표를 출력한다. 판정 값:
- represented: 같은 제약이 전송 스키마에 키워드로 있다(서버 문법이 그 키워드를 강제하는지는 별개 — 레포 밖 탐침의 몫).
- missing: Pydantic에는 있는데 전송 스키마에 없다(측정 장치 결함 후보).
- not_expressible: 검증 함수라 JSON 스키마로 표현할 수 없다(문법이 막지 못하고 게이트에서만 걸린다).
- excluded: 의도적으로 뺐다(LLM 초안의 range, LLM이 만들지 않는 advisory_signals — §2.8).

범위(정직 표기): 이 도구는 우리 쪽 두 정의의 차이만 본다. llama.cpp 문법이 어떤 키워드를 건너뛰는지는 알 수 없다.
"""
from __future__ import annotations

import json
import uuid
from typing import Annotated, Any, Final, Literal, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from sentinel.output_schema import AnalysisDraft
from sentinel.pipeline.llm_prompt import LLM_DROPPED_FIELDS, TRANSMISSION_SCHEMA

KEYWORD_OF: Final = {"uuid": "format", "min_length": "minItems", "ge": "minimum", "extra_forbid": "additionalProperties",
                     "literal": "enum/const", "pattern": "pattern"}


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


def gaps(root: type[BaseModel] = AnalysisDraft, schema: dict[str, Any] = TRANSMISSION_SCHEMA) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def visit(model: type[BaseModel], node: dict[str, Any] | None, path: str) -> None:
        if model.model_config.get("extra") == "forbid":
            rows.append(_row(path or "(root)", "extra_forbid", node))
        for d in model.__pydantic_decorators__.model_validators.values():
            rows.append({"path": path or "(root)", "pydantic": f"validator:{d.func.__name__}", "schema": "-", "verdict": "not_expressible"})
        for name, field in model.model_fields.items():
            here = f"{path}.{name}" if path else name
            child = None if node is None else node.get("properties", {}).get(name)
            if name in LLM_DROPPED_FIELDS:
                rows.append({"path": here, "pydantic": "field", "schema": "-", "verdict": "excluded"})
                continue
            annotation = field.annotation
            base = get_args(annotation)[0] if get_origin(annotation) is Annotated else annotation
            for constraint in _constraints(field, base, model, name):
                rows.append(_row(here, constraint, child))
            is_list = get_origin(base) in (list, tuple)
            if child is not None and child.get("maxItems") == 0:
                rows.append({"path": here, "pydantic": "field", "schema": "maxItems 0", "verdict": "excluded"})
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


def main() -> int:
    rows = gaps()
    print("| 경로 | Pydantic 제약 | 전송 스키마 | 판정 |")
    print("|---|---|---|---|")
    for row in rows:
        print(f"| {row['path']} | {row['pydantic']} | {row['schema']} | {row['verdict']} |")
    print(json.dumps({v: sum(1 for r in rows if r["verdict"] == v) for v in ("represented", "missing", "not_expressible", "excluded")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
