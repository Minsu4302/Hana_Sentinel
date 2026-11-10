"""LLM 초안 계약의 전달 — (A) §2.8, `llm_contract_conveyed`.

초안 계약(Pydantic)의 모든 하위 제약은 셋 중 하나다: 전송 스키마에 표현됨 / 프롬프트 출력 규칙 절에 열거됨 /
정당한 제외(초안 금지 — 근거 표에 있는 필드만). 새 제약이나 새 검증기가 생기면 고정 테스트가 실패한다.
전달만 보장한다 — 모델이 지키는지는 게이트가 판정한다.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import AfterValidator, BaseModel, ConfigDict, TypeAdapter, ValidationError
from typing import Annotated

from sentinel.common_types import POINTER_PATTERN, JsonPointer
from sentinel.pipeline import llm_prompt
from sentinel.pipeline.llm_prompt import OUTPUT_RULES, RULES_HEADING, SYSTEM_PROMPT, TRANSMISSION_SCHEMA
from tests.test_rule_wiring import _run_mutant
from tools.eval.schema_gap import EXCLUSION_BASIS, SUBCONSTRAINTS, gaps
from tools.mutation_guard import copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
CONVEYED = {"represented", "conveyed_by_rule", "excluded"}
RESP_PATH = "findings[].evidence[].pointer{locus=resp_body}.body{kind=json}.path"
REQ_PATH = "findings[].evidence[].pointer{locus=req_body}.body{kind=json}.path"
SYNTAX = "validator:_check_json_pointer/json_pointer.syntax"
NO_DASH = "validator:_check_json_pointer/json_pointer.no_dash_token"
ONE_NODE = "validator:_check_json_pointer/json_pointer.one_node"


def _verdicts(rows) -> dict:
    return {(r["path"], r["pydantic"]): r["verdict"] for r in rows}


def _not_conveyed(rows) -> list[dict]:
    return [r for r in rows if r["verdict"] not in CONVEYED]


def _body_json(schema: dict) -> dict:
    evidence = schema["properties"]["findings"]["items"]["properties"]["evidence"]["items"]
    for branch in evidence["properties"]["pointer"]["oneOf"]:
        body = branch["properties"].get("body")
        if body:
            return next(b for b in body["oneOf"] if b["properties"]["kind"].get("const") == "json")
    raise AssertionError("본문 변형 없음")


# ── 고정 테스트 ────────────────────────────────────────────────────

def test_every_draft_constraint_is_conveyed_or_legitimately_excluded():
    rows = gaps()
    assert _not_conveyed(rows) == []
    assert {r["basis"] for r in rows if r["verdict"] == "excluded"} <= set(EXCLUSION_BASIS.values())


def test_json_pointer_is_judged_per_subconstraint():
    verdicts = _verdicts(gaps())
    for path in (REQ_PATH, RESP_PATH):
        assert verdicts[(path, SYNTAX)] == "represented"
        assert verdicts[(path, NO_DASH)] == "conveyed_by_rule"
        assert verdicts[(path, ONE_NODE)] == "conveyed_by_rule"


def test_only_range_and_advisories_are_excluded():
    excluded = {r["path"].rsplit(".", 1)[-1] for r in gaps() if r["verdict"] == "excluded"}
    assert excluded == {"range", "advisory_signals"}


def test_every_output_rule_belongs_to_a_known_subconstraint():
    known = {sub_id for subs in SUBCONSTRAINTS.values() for sub_id, _ in subs}
    assert set(OUTPUT_RULES) <= known


def test_rendered_prompt_lists_every_rule_under_the_heading_only():
    before, after = SYSTEM_PROMPT.split(RULES_HEADING, 1)
    for sentences in OUTPUT_RULES.values():
        for sentence in sentences:
            assert f"- {sentence}" in after.splitlines() and sentence not in before
    assert llm_prompt.RULES_SLOT not in llm_prompt.TEMPLATE_TEXT


def test_schema_carries_the_rfc_pattern_and_nothing_narrower():
    assert _body_json(TRANSMISSION_SCHEMA)["properties"]["path"]["pattern"] == POINTER_PATTERN


def test_contract_itself_is_unchanged_by_the_schema_pattern():
    pointer = TypeAdapter(JsonPointer)
    for good in ("", "/a/0", "/a.b", "/items[0].id", "/a-b/-x", "/~0~1"):
        assert pointer.validate_python(good) == good  # 키에 점·대괄호가 있어도 가리킬 수 있다
    for bad in ("a.b", "/items/-", "/-/x", "/~2"):
        with pytest.raises(ValidationError):
            pointer.validate_python(bad)


# ── 위조 거부 ──────────────────────────────────────────────────────

def test_dropped_pattern_makes_the_syntax_missing():
    schema = copy.deepcopy(TRANSMISSION_SCHEMA)
    del _body_json(schema)["properties"]["path"]["pattern"]
    verdicts = _verdicts(gaps(schema=schema))
    assert verdicts[(RESP_PATH, SYNTAX)] == "missing"


def test_a_different_pattern_does_not_count_as_the_contract():
    schema = copy.deepcopy(TRANSMISSION_SCHEMA)
    _body_json(schema)["properties"]["path"]["pattern"] = r"^(/[a-z0-9]*)*$"  # 계약보다 좁다
    assert _verdicts(gaps(schema=schema))[(RESP_PATH, SYNTAX)] == "missing"


def test_one_missing_rule_is_not_covered_by_the_schema_pattern():
    sentence = OUTPUT_RULES["json_pointer.no_dash_token"][0]
    verdicts = _verdicts(gaps(prompt=SYSTEM_PROMPT.replace(f"- {sentence}", "")))
    assert verdicts[(RESP_PATH, NO_DASH)] == "missing"
    assert verdicts[(RESP_PATH, SYNTAX)] == "represented" and verdicts[(RESP_PATH, ONE_NODE)] == "conveyed_by_rule"


def test_partial_rule_does_not_convey_the_subconstraint():
    sentence = OUTPUT_RULES["json_pointer.one_node"][1]
    assert _verdicts(gaps(prompt=SYSTEM_PROMPT.replace(f"- {sentence}", "")))[(RESP_PATH, ONE_NODE)] == "missing"


def test_rule_outside_the_section_does_not_count():
    sentence = OUTPUT_RULES["json_pointer.no_dash_token"][0]
    before, after = SYSTEM_PROMPT.split(RULES_HEADING, 1)
    moved = f"- {sentence}\n" + before + RULES_HEADING + after.replace(f"- {sentence}", "")
    assert _verdicts(gaps(prompt=moved))[(RESP_PATH, NO_DASH)] == "missing"


def test_rule_table_without_the_id_does_not_convey_it():
    rules = {k: v for k, v in OUTPUT_RULES.items() if k != "json_pointer.one_node"}
    assert _verdicts(gaps(rules=rules))[(RESP_PATH, ONE_NODE)] == "missing"


def test_exclusion_without_a_basis_is_missing():
    schema = copy.deepcopy(TRANSMISSION_SCHEMA)
    schema["properties"]["findings"]["items"]["properties"]["evidence"]["maxItems"] = 0  # 근거 없이 막아 버림
    row = next(r for r in gaps(schema=schema) if r["path"] == "findings[].evidence" and r["pydantic"] == "field")
    assert row["verdict"] == "missing" and row["basis"] == "근거 없는 제외"


def _no_vowels(value: str) -> str:
    if set(value) & set("aeiou"):
        raise ValueError("x")
    return value


class _NewContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Annotated[str, AfterValidator(_no_vowels)]


def test_new_validator_without_a_decomposition_fails_the_fixed_check():
    rows = gaps(root=_NewContract, schema=_NewContract.model_json_schema())
    assert [(r["pydantic"], r["verdict"]) for r in _not_conveyed(rows)] == [("validator:_no_vowels", "not_expressible")]


def test_template_without_the_rules_slot_is_refused():
    with pytest.raises(ValueError):
        llm_prompt._with_rules(llm_prompt.TEMPLATE_PATH.read_text(encoding="utf-8").replace(llm_prompt.RULES_SLOT, ""))


# ── 변이 확인 ──────────────────────────────────────────────────────

_C = "tests/test_llm_contract_conveyed.py::"
FIXED = _C + "test_every_draft_constraint_is_conveyed_or_legitimately_excluded"
SRC_MUTATIONS = {
    "rule_deleted": ("sentinel/pipeline/llm_prompt.py", "sentinel.pipeline.llm_prompt",
                     '    "json_pointer.no_dash_token": ("A body path never uses - as a whole segment (not /items/-).",),\n', "", [FIXED]),
    "pattern_dropped": ("sentinel/common_types.py", "sentinel.common_types",
                        ', Field(json_schema_extra={"pattern": POINTER_PATTERN})]', "]", [FIXED]),
}
TOOL_MUTATIONS = {
    "subconstraints_bundled": ("tools/eval/schema_gap.py", "tools.eval.schema_gap",
                               "rows.append(_sub_row(path, func, sub_id, in_schema, node, lines, rules))",
                               "rows.append(_sub_row(path, func, sub_id, SUBCONSTRAINTS[func][0][1], node, lines, rules))",
                               [_C + "test_one_missing_rule_is_not_covered_by_the_schema_pattern"]),
    "rule_anywhere": ("tools/eval/schema_gap.py", "tools.eval.schema_gap", "prompt.split(RULES_HEADING, 1)[1].splitlines()",
                      "prompt.splitlines()", [_C + "test_rule_outside_the_section_does_not_count"]),
    "exclusion_without_basis": ("tools/eval/schema_gap.py", "tools.eval.schema_gap", '"verdict": "missing", "basis": "근거 없는 제외"',
                                '"verdict": "excluded", "basis": "근거 없는 제외"', [_C + "test_exclusion_without_a_basis_is_missing"]),
}


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_conveyance_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_conveyance_judge_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
