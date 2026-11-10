"""LLM 초안 계약의 전달 — (A) §2.8, `llm_contract_conveyed`.

초안 계약(Pydantic)의 모든 하위 제약은 셋 중 하나다: 전송 스키마에 표현됨 / 프롬프트 출력 규칙 절에 열거됨 /
정당한 제외(초안 금지 — 근거 표에 있는 필드만). 새 제약이나 새 검증기가 생기면 고정 테스트가 실패한다.
게이트 검사(`output_gate.DRAFT_CHECKS`)도 검사마다 전달 수단(초안 계약 / 기존 Rules: 문장 원문 / 출력 규칙)이 있어야 한다.
전달만 보장한다 — 모델이 지키는지는 게이트가 판정한다.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from pydantic import AfterValidator, BaseModel, ConfigDict, TypeAdapter, ValidationError
from typing import Annotated

from sentinel.common_types import POINTER_PATTERN, JsonPointer
from sentinel.pipeline import llm_prompt, output_gate
from sentinel.pipeline.llm_prompt import OUTPUT_RULES, RULES_HEADING, SYSTEM_PROMPT, TRANSMISSION_SCHEMA
from tests.test_rule_wiring import _run_mutant
from tools.eval.schema_gap import EXCLUSION_BASIS, GATE_CHECKS, SUBCONSTRAINTS, T_POINTER, T_REF, gate_checks, gaps
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


def test_every_output_rule_belongs_to_a_known_subconstraint_or_gate_check():
    known = {sub_id for subs in SUBCONSTRAINTS.values() for sub_id, _ in subs}
    known |= {m[1] for _symbol, means in GATE_CHECKS.values() for m in means if m[0] == "output_rule"}
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


# ── 게이트 검사의 전달 ─────────────────────────────────────────────

def _gate(rows) -> dict:
    return {r["check"]: r["verdict"] for r in rows}


def test_every_gate_check_is_listed_and_conveyed():
    rows = gate_checks()
    assert [r["check"] for r in rows] == list(output_gate.DRAFT_CHECKS)
    assert [r for r in rows if r["verdict"] != "conveyed"] == []


def test_every_gate_check_names_an_existing_gate_judgement():
    for check, (symbol, means) in GATE_CHECKS.items():
        assert callable(getattr(output_gate, symbol, None)), check
        assert means, check


def test_registered_existing_rules_are_verbatim_lines_of_the_unchanged_template():
    section = SYSTEM_PROMPT.split("\nRules:\n", 1)[1].split(RULES_HEADING, 1)[0].splitlines()
    for symbol, means in GATE_CHECKS.values():
        for m in means:
            if m[0] == "rule":
                assert f"- {m[1]}" in section


def test_new_gate_rules_are_in_the_output_rules_section():
    for key in ("gate.locus_names", "gate.occurrence", "gate.body_kind"):
        assert OUTPUT_RULES[key]
    verdicts = _gate(gate_checks())
    for check in ("locus_names", "header_occurrence_by_name", "param_occurrence_by_location_and_name",
                  "body_json_needs_json_content", "body_json_needs_untruncated"):
        assert verdicts[check] == "conveyed"


def test_deleted_existing_rule_leaves_its_checks_missing():
    verdicts = _gate(gate_checks(prompt=SYSTEM_PROMPT.replace(f"- {T_REF}", "")))
    assert verdicts["transaction_ref_in_analyzed"] == "missing"


def test_existing_rule_moved_into_output_rules_does_not_count_as_registered():
    before, after = SYSTEM_PROMPT.split(RULES_HEADING, 1)
    moved = before.replace(f"- {T_POINTER}", "") + RULES_HEADING + after + f"\n- {T_POINTER}"
    verdicts = _gate(gate_checks(prompt=moved))
    assert verdicts["header_name_case_insensitive"] == "missing" and verdicts["body_needs_content"] == "missing"


@pytest.mark.parametrize("key, check", [("gate.locus_names", "locus_names"), ("gate.occurrence", "header_occurrence_by_name"),
                                        ("gate.body_kind", "body_json_needs_untruncated")])
def test_deleted_output_rule_leaves_its_gate_check_missing(key, check):
    sentence = OUTPUT_RULES[key][0]
    assert _gate(gate_checks(prompt=SYSTEM_PROMPT.replace(f"- {sentence}", "")))[check] == "missing"


def test_contract_gap_makes_contract_backed_checks_missing():
    sentence = OUTPUT_RULES["json_pointer.one_node"][1]
    verdicts = _gate(gate_checks(prompt=SYSTEM_PROMPT.replace(f"- {sentence}", "")))
    assert verdicts["body_json_one_node"] == "missing" and verdicts["draft_schema"] == "missing"


def test_every_draft_reason_code_maps_to_a_gate_check():
    assert set(output_gate.CHECKS_OF_REASON) | output_gate.NOT_FROM_DRAFT == set(output_gate.REASON_CODES)
    assert not set(output_gate.CHECKS_OF_REASON) & output_gate.NOT_FROM_DRAFT
    for code, checks in output_gate.CHECKS_OF_REASON.items():
        assert checks and set(checks) <= set(output_gate.DRAFT_CHECKS), code
    assert set(output_gate.CHECKS_OF_REASON["pointer_unresolvable"]) >= {"locus_names", "body_json_needs_json_content",
                                                                           "body_json_needs_untruncated", "header_occurrence_by_name"}


def test_check_without_any_means_is_missing():
    checks = {**GATE_CHECKS, "body_json_needs_untruncated": ("_body_resolves", ())}
    assert _gate(gate_checks(checks=checks))["body_json_needs_untruncated"] == "missing"


# ── 변이 확인 ──────────────────────────────────────────────────────

_C = "tests/test_llm_contract_conveyed.py::"
FIXED = _C + "test_every_draft_constraint_is_conveyed_or_legitimately_excluded"
SRC_MUTATIONS = {
    "rule_deleted": ("sentinel/pipeline/llm_prompt.py", "sentinel.pipeline.llm_prompt",
                     '    "json_pointer.no_dash_token": ("A body path never uses - as a whole segment (not /items/-).",),\n', "", [FIXED]),
    "pattern_dropped": ("sentinel/common_types.py", "sentinel.common_types",
                        ', Field(json_schema_extra={"pattern": POINTER_PATTERN})]', "]", [FIXED]),
}
GATE_FIXED = _C + "test_every_gate_check_is_listed_and_conveyed"
SRC_MUTATIONS["reason_code_unmapped"] = ("sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate",
                                         '    "llm_range_present": ("llm_no_range",),\n', "",
                                         [_C + "test_every_draft_reason_code_maps_to_a_gate_check"])
GATE_RULE_MUTATIONS = {  # 출력 규칙 1~3 중 하나 삭제 → 실패
    "locus_rule_deleted": '    "gate.locus_names": (',
    "occurrence_rule_deleted": '    "gate.occurrence": (',
    "body_kind_rule_deleted": '    "gate.body_kind": (',
}
EXISTING_RULE_LINE = "- evidence.transaction_ref copies transaction_id exactly.\n"
TOOL_MUTATIONS = {
    "subconstraints_bundled": ("tools/eval/schema_gap.py", "tools.eval.schema_gap",
                               "rows.append(_sub_row(path, func, sub_id, in_schema, node, lines, rules))",
                               "rows.append(_sub_row(path, func, sub_id, SUBCONSTRAINTS[func][0][1], node, lines, rules))",
                               [_C + "test_one_missing_rule_is_not_covered_by_the_schema_pattern"]),
    "rule_anywhere": ("tools/eval/schema_gap.py", "tools.eval.schema_gap", "prompt.split(RULES_HEADING, 1)[1].splitlines()",
                      "prompt.splitlines()", [_C + "test_rule_outside_the_section_does_not_count"]),
    "exclusion_without_basis": ("tools/eval/schema_gap.py", "tools.eval.schema_gap", '"verdict": "missing", "basis": "근거 없는 제외"',
                                '"verdict": "excluded", "basis": "근거 없는 제외"', [_C + "test_exclusion_without_a_basis_is_missing"]),
    "gate_check_dropped_from_table": ("tools/eval/schema_gap.py", "tools.eval.schema_gap",
                                      '    "body_json_needs_untruncated": ("_body_resolves", (("output_rule", "gate.body_kind"),)),\n', "",
                                      [GATE_FIXED]),
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


def _rule_entry(source: str, prefix: str) -> str:
    """OUTPUT_RULES에서 prefix로 시작하는 항목 하나(다음 항목 앞까지)."""
    start = source.index(prefix)
    end = source.index("\n    \"", start + 1)
    return source[start:end + 1]


@pytest.mark.parametrize("name", sorted(GATE_RULE_MUTATIONS))
def test_gate_output_rules_are_load_bearing_under_verified_mutation(tmp_path, name):
    rel = "sentinel/pipeline/llm_prompt.py"
    entry = _rule_entry((REPO_ROOT / "src" / rel).read_text(encoding="utf-8"), GATE_RULE_MUTATIONS[name])
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, entry, "")
    _run_mutant([root, REPO_ROOT], "sentinel.pipeline.llm_prompt", [GATE_FIXED], mutant)


def test_existing_rule_deleted_from_the_template_is_caught_under_verified_mutation(tmp_path):
    root = tmp_path / "mut" / "src"
    copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, "sentinel/pipeline/prompts/analysis.txt", EXISTING_RULE_LINE, "")
    _run_mutant([root, REPO_ROOT], "sentinel.pipeline.llm_prompt", [GATE_FIXED], (root / "sentinel/pipeline/llm_prompt.py").resolve())
