"""규칙 엔진 — (A) §3.0 ④, §2.4. 규칙별 양성·음성, hard negative 대조, MaskedRef 건너뜀, 최악 입력 시간 예산.

여기서는 규칙 함수 단위만 본다. ④ 결선과 게이트 경로는 `tests/test_rule_wiring.py`.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

import pytest

from sentinel.common_types import BodyLocator, HeaderLocator, ParamLocator
from sentinel.output_schema import SERVER_ASSIGNED_FIELDS, FindingDraft
from sentinel.pipeline import output_gate, rule_engine
from sentinel.pipeline.rule_engine import (
    STACK_TRACE_PATTERNS, cors_reflection_rule, cors_rule, evaluate, reflection_rule, stack_trace_rule)
from sentinel.schema import Transaction
from tools.eval.frozen_rulesets import FROZEN_RULESETS, RULESET_SCOPE_HISTORY, current_ruleset_hash, frozen_file_hash

REF = uuid.UUID("00000000-0000-4000-8000-0000000000d4")
MASKED = {"masked": True, "label": None, "kind": "token"}
PAYLOAD = "<b>x</b>"
BUDGET_SECONDS = 5.0  # 설정값: 선형이면 수십 ms, 다항이면 수 분 — 그 사이 어디든 판별된다
MAX_BODY = 256 * 1024


def _body(content, ctype="application/json", truncated=False, encoding="utf8") -> dict:
    return {"content_type": ctype, "size_bytes": 0 if content is None else len(content.encode()), "truncated": truncated,
            "encoding": encoding, "content": content}


def _tx(params=(), headers=(), body=None, req_headers=()) -> Transaction:
    doc = {"meta": {"transaction_id": str(REF), "captured_at": "2026-10-27T10:00:00+09:00", "origin_ref": "burp-1",
                    "sanitization": {"applied": True, "failed": False, "policy_version": "p1", "redacted_count": 0,
                                     "redacted_kinds": {"token": 0, "cookie": 0, "pii": 0, "host": 0}}},
           "request": {"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": 3000, "path": "/rest/x",
                       "query_params": [{"name": n, "value": v, "location": loc} for n, v, loc in params],
                       "headers": [{"name": n, "value": v} for n, v in req_headers], "body": _body("", "text/plain")},
           "response": {"status": 200, "headers": [{"name": n, "value": v} for n, v in headers],
                        "body": body or _body("{}"), "elapsed_ms": 1}}
    return Transaction.model_validate_json(json.dumps(doc))


def _q(value, name="q", location="query") -> tuple:
    return (name, value, location)


def _pointer(finding: FindingDraft, index: int = -1):
    return finding.evidence[index].pointer


# ── 공통: 초안의 모양 ──────────────────────────────────────────────

ALL_FIRE = _tx([_q(PAYLOAD)], [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")],
               _body(json.dumps({"q": PAYLOAD, "stack": "Error\n    at /app/a.ts:1:2"})))


def test_every_rule_fires_once_on_a_transaction_with_all_three_defects():
    assert sorted(d.category for d in evaluate(ALL_FIRE)) == ["info_exposure", "reflected_injection_indicator",
                                                              "security_misconfig"]


def test_drafts_claim_only_observation_and_carry_no_server_assigned_field():
    for draft in evaluate(ALL_FIRE):
        assert draft.claim_basis == "observed" and draft.limitations and draft.next_steps
        assert not set(draft.model_dump()) & SERVER_ASSIGNED_FIELDS
        for evidence in draft.evidence:
            assert not set(evidence.model_dump()) & SERVER_ASSIGNED_FIELDS


def test_all_rule_evidence_resolves_on_its_transaction():
    for draft in evaluate(ALL_FIRE):
        assert all(output_gate.resolves(e.pointer, ALL_FIRE) for e in draft.evidence)


def test_clean_transaction_fires_nothing():
    assert evaluate(_tx([_q("apple")], [("Content-Type", "application/json")], _body('{"q": "apple"}'))) == []


def test_ruleset_frozen_before_s_v2_test_is_rules_2():
    """(A) §6.2 (b): S v2 test 작성 전 동결된 값. 바꾸면 그 위의 test 주장도 함께 다시 봐야 한다."""
    assert rule_engine.RULESET_VERSION == "rules-2"


def test_ruleset_files_match_the_frozen_hash_of_their_ruleset():
    assert rule_engine.RULESET_VERSION in FROZEN_RULESETS
    assert current_ruleset_hash() == FROZEN_RULESETS[rule_engine.RULESET_VERSION]


def test_scope_extension_of_rules_2_kept_the_rule_file_as_it_was():
    """범위만 넓혔다 — rule_engine.py는 확장 전 기록과 같다."""
    assert frozen_file_hash(Path(rule_engine.__file__)) == RULESET_SCOPE_HISTORY["rules-2"]


def test_frozen_hash_does_not_depend_on_the_checkout_line_endings(tmp_path):
    lf, crlf = tmp_path / "lf.py", tmp_path / "crlf.py"
    lf.write_bytes(b"a = 1\nb = 2\n")
    crlf.write_bytes(b"a = 1\r\nb = 2\r\n")
    assert frozen_file_hash(lf) == frozen_file_hash(crlf)


# ── ④ 반사 ───────────────────────────────────────────────────────

def test_reflection_in_a_json_node_points_at_the_param_and_the_node():
    [finding] = reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"data": [], "query": PAYLOAD}))))
    assert finding.category == "reflected_injection_indicator"
    assert _pointer(finding, 0) == ParamLocator(locus="req_param", location="query", name="q", occurrence=0)
    assert isinstance(_pointer(finding), BodyLocator) and _pointer(finding).body.path == "/query"


def test_reflection_is_read_from_the_decoded_json_value_not_the_raw_token():
    """값의 `"`는 raw JSON에서 `\\"`로 나타난다 — 디코드해서 봐야 일치한다."""
    value = 'a"b'
    assert '"a"b"' not in json.dumps({"v": value})
    assert len(reflection_rule(_tx([_q(value)], body=_body(json.dumps({"v": value}))))) == 1


def test_reflection_inside_a_longer_value_is_an_exact_substring_match():
    assert len(reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"v": f"결과: {PAYLOAD} 없음"}))))) == 1


def test_reflection_in_a_text_body_points_at_the_first_occurrence():
    content = f"앞 {PAYLOAD} 뒤 {PAYLOAD}"
    [finding] = reflection_rule(_tx([_q(PAYLOAD)], body=_body(content, "text/html")))
    rng = _pointer(finding).body.range
    assert (rng.start, rng.end) == (2, 2 + len(PAYLOAD))


def test_form_param_is_checked_too():
    [finding] = reflection_rule(_tx([_q(PAYLOAD, location="form")], body=_body(json.dumps({"v": PAYLOAD}))))
    assert _pointer(finding, 0).location == "form"


def test_each_occurrence_of_a_repeated_param_is_addressed_by_its_own_occurrence():
    findings = reflection_rule(_tx([_q("plain"), _q(PAYLOAD)], body=_body(json.dumps({"v": PAYLOAD}))))
    assert [_pointer(f, 0).occurrence for f in findings] == [1]


def test_multi_node_reflection_uses_only_the_first_node_in_cna_order():
    """문서 순서는 /z가 먼저지만 CNA 순으로는 /a가 먼저다."""
    [finding] = reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"z": PAYLOAD, "a": PAYLOAD}))))
    assert _pointer(finding).body.path == "/a" and len(finding.evidence) == 2


@pytest.mark.parametrize("escaped", ["&lt;b&gt;x&lt;/b&gt;", "&#60;b&#62;x&#60;/b&#62;", "&#x3c;b&#x3e;x&#x3c;/b&#x3e;",
                                     "%3Cb%3Ex%3C/b%3E", "bx/b"])
def test_hard_negative_escaped_or_stripped_reflection_does_not_fire(escaped):
    assert reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"v": escaped})))) == []


def test_escaped_form_does_not_suppress_a_raw_form_next_to_it():
    """이스케이프 목록은 문서이지 억제 로직이 아니다: 같은 값이 이스케이프형과 원형으로 둘 다 나오면 발화."""
    tx = _tx([_q(PAYLOAD)], body=_body(json.dumps({"a": "&lt;b&gt;x&lt;/b&gt;", "b": PAYLOAD})))
    [finding] = reflection_rule(tx)
    assert _pointer(finding).body.path == "/b"


def test_value_without_html_special_chars_does_not_fire():
    assert reflection_rule(_tx([_q("apple")], body=_body(json.dumps({"v": "apple"})))) == []


@pytest.mark.parametrize("char", list("<>\"'"))
def test_each_trigger_char_alone_is_enough(char):
    value = f"x{char}y"
    assert len(reflection_rule(_tx([_q(value)], body=_body(json.dumps({"v": value}))))) == 1


def test_json_member_names_are_not_reflection_sites():
    assert reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({PAYLOAD: "v"})))) == []


def test_masked_param_is_skipped_but_still_counts_for_occurrence():
    findings = reflection_rule(_tx([_q(MASKED), _q(PAYLOAD)], body=_body(json.dumps({"v": PAYLOAD}))))
    assert [_pointer(f, 0).occurrence for f in findings] == [1]


@pytest.mark.parametrize("body", [_body(None, encoding="omitted"), _body("PGI+eDwvYj4=", encoding="base64"),
                                  _body(json.dumps({"v": PAYLOAD}), truncated=True)],
                         ids=["omitted", "base64", "truncated"])
def test_unreadable_or_truncated_bodies_are_not_inspected_for_reflection(body):
    assert reflection_rule(_tx([_q(PAYLOAD)], body=body)) == []


def test_hypothesis_names_the_param_but_never_carries_its_value():
    marker = "<marker-value>"
    [finding] = reflection_rule(_tx([_q(marker)], body=_body(json.dumps({"v": marker}))))
    assert "`q`" in finding.hypothesis and marker not in json.dumps(finding.model_dump(mode="json"), ensure_ascii=False)


def test_limitations_state_the_json_escape_and_path_header_blind_spots():
    [finding] = reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"v": PAYLOAD}))))
    assert "JSON 문자열 이스케이프는 이스케이프로 보지 않는다(소비 측 복원 가정)" in finding.limitations
    assert "경로·헤더 값의 반사는 보지 않는다" in finding.limitations


def test_node_under_a_dash_key_cannot_be_pointed_at_so_it_is_skipped_without_crashing():
    """Locator는 '-' 세그먼트를 표현하지 못한다((A) §2.6 한계)."""
    assert reflection_rule(_tx([_q(PAYLOAD)], body=_body(json.dumps({"-": PAYLOAD})))) == []


# ── ② 스택 트레이스 ───────────────────────────────────────────────

TRACES = {
    "node": "Error: x\n    at Object.<anonymous> (/app/a.js:10:15)",
    "node_bare": "Error\n    at /app/routes/product.ts:41:13",
    "node_crlf": "Error\r\n    at /app/a.js:10:15\r\n",
    "java_frame": "at com.example.Foo.bar(Foo.java:42)",
    "java_header": 'Exception in thread "main" java.lang.RuntimeException',
    "python_header": "Traceback (most recent call last):",
    "python_frame": 'File "/app/x.py", line 12',
    "dotnet": r"at App.Foo.Bar(String s) in C:\src\Foo.cs:line 12",
    "php_line": "Fatal error in /var/www/x.php on line 3",
    "php_trace": "Stack trace:\n#0 {main}",
}


def test_every_stack_pattern_has_a_sample():
    hit = {p.pattern for sample in TRACES.values() for p in STACK_TRACE_PATTERNS if p.search(sample)}
    assert hit == {p.pattern for p in STACK_TRACE_PATTERNS}


@pytest.mark.parametrize("name", sorted(TRACES))
def test_stack_trace_in_a_json_node_fires_with_one_evidence(name):
    [finding] = stack_trace_rule(_tx(body=_body(json.dumps({"error": {"stack": TRACES[name]}}))))
    assert finding.category == "info_exposure" and len(finding.evidence) == 1
    assert _pointer(finding).body.path == "/error/stack"


@pytest.mark.parametrize("name", sorted(TRACES))
def test_stack_trace_in_a_text_body_points_at_the_earliest_match(name):
    content = "앞\n" + TRACES[name]
    [finding] = stack_trace_rule(_tx(body=_body(content, "text/plain")))
    rng = _pointer(finding).body.range
    assert rng.start >= 2 and rng.end <= len(content)


def test_stack_trace_in_truncated_body_is_read_as_text():
    tx = _tx(body=_body('{"stack": "' + "Traceback (most recent call last):", truncated=True))
    [finding] = stack_trace_rule(tx)
    assert _pointer(finding).body.kind == "text" and output_gate.resolves(_pointer(finding), tx)


def test_several_trace_nodes_give_one_finding_on_the_first_node_in_cna_order():
    trace = TRACES["node_bare"]
    [finding] = stack_trace_rule(_tx(body=_body(json.dumps({"z": trace, "a": trace}))))
    assert _pointer(finding).body.path == "/a"


@pytest.mark.parametrize("text", ["look at the sky", "at noon: 12:30", "File not found", "Exception handled",
                                  "line 12 of the report", "traceback was disabled"])
def test_prose_near_the_patterns_does_not_fire(text):
    assert stack_trace_rule(_tx(body=_body(json.dumps({"message": text})))) == []


def test_trace_in_a_json_member_name_does_not_fire():
    assert stack_trace_rule(_tx(body=_body(json.dumps({TRACES["python_header"]: 1})))) == []


@pytest.mark.parametrize("body", [_body(None, encoding="omitted"), _body("VHJhY2ViYWNr", encoding="base64")],
                         ids=["omitted", "base64"])
def test_unreadable_bodies_are_not_inspected_for_traces(body):
    assert stack_trace_rule(_tx(body=body)) == []


WORST_INPUTS = {
    "newlines": "\n" * MAX_BODY,
    "spaces_one_line": " " * MAX_BODY,
    "at_long_single_line": "at " + "a" * MAX_BODY,
    "at_colons": "at " + ":1" * (MAX_BODY // 2),
    "at_repeated": "at " * (MAX_BODY // 3),
    "at_lines": "at x\n" * (MAX_BODY // 5),
    "java_open_paren": "at a(" * (MAX_BODY // 5),
    "dotnet_repeated": "at a() in " * (MAX_BODY // 10),
    "dotnet_nested_parens": "at a(" + ")" * MAX_BODY,
    "python_unclosed": 'File "' * (MAX_BODY // 6),
    "php_trace_ws": "Stack trace:" + " " * MAX_BODY,
}


@pytest.mark.parametrize("name", sorted(WORST_INPUTS))
def test_stack_rule_on_a_worst_case_256kb_body_stays_within_the_time_budget(name):
    content = WORST_INPUTS[name]
    tx = _tx(body=_body(content, "text/plain"))
    started = time.perf_counter()
    stack_trace_rule(tx)
    assert time.perf_counter() - started < BUDGET_SECONDS


def test_stack_patterns_have_no_unbounded_wildcard_next_to_another_repeat():
    """`.+`·`.*`는 줄을 건너지 않아도 서로 겹치면 다항이다 — 패턴 전체에서 쓰지 않는다."""
    assert not [p.pattern for p in STACK_TRACE_PATTERNS if re.search(r"\.[+*]", p.pattern)]


# ── ③ CORS ───────────────────────────────────────────────────────

ACAO, ACAC = "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"


def test_wildcard_origin_with_credentials_fires_with_two_header_evidence():
    [finding] = cors_rule(_tx(headers=[(ACAO, "*"), (ACAC, "true")]))
    assert finding.category == "security_misconfig"
    assert [e.pointer for e in finding.evidence] == [
        HeaderLocator(locus="resp_header", name="access-control-allow-origin"),
        HeaderLocator(locus="resp_header", name="access-control-allow-credentials")]


@pytest.mark.parametrize("headers", [
    [(ACAO.upper(), "*"), (ACAC.lower(), "true")],
    [(ACAO, "  *  "), (ACAC, " true ")],
], ids=["name_case", "value_trim"])
def test_header_name_case_and_value_whitespace_do_not_matter(headers):
    tx = _tx(headers=headers)
    [finding] = cors_rule(tx)
    assert all(output_gate.resolves(e.pointer, tx) for e in finding.evidence)


@pytest.mark.parametrize("headers", [
    [(ACAO, "*")],
    [(ACAC, "true")],
    [(ACAO, "https://a.example"), (ACAC, "true")],
    [(ACAO, "*"), (ACAC, "false")],
    [(ACAO, "*"), (ACAC, "TRUE")],
    [(ACAO, "*"), (ACAO, "*"), (ACAC, "true")],
    [(ACAO, "*"), (ACAC, "true"), (ACAC.lower(), "true")],
    [(ACAO, MASKED), (ACAC, "true")],
    [(ACAO, "*"), (ACAC, MASKED)],
], ids=["no_acac", "no_acao", "specific_origin", "credentials_false", "value_is_case_sensitive", "duplicate_acao",
        "duplicate_acac_mixed_case", "masked_acao", "masked_acac"])
def test_other_header_combinations_do_not_fire(headers):
    assert cors_rule(_tx(headers=headers)) == []


# ── ③' CORS 출처 반사 ─────────────────────────────────────────────

ORIGIN = "https://a.example"


def _origin_tx(req=(("Origin", ORIGIN),), resp=((ACAO, ORIGIN), (ACAC, "true"))) -> Transaction:
    return _tx(headers=resp, req_headers=req)


def test_reflected_origin_with_credentials_fires_with_three_header_evidence():
    tx = _origin_tx()
    [finding] = cors_reflection_rule(tx)
    assert finding.category == "security_misconfig" and finding.claim_basis == "observed"
    assert [e.pointer for e in finding.evidence] == [
        HeaderLocator(locus="req_header", name="origin"),
        HeaderLocator(locus="resp_header", name="access-control-allow-origin"),
        HeaderLocator(locus="resp_header", name="access-control-allow-credentials")]
    assert all(output_gate.resolves(e.pointer, tx) for e in finding.evidence)


def test_reflected_origin_states_its_limits_and_leaves_the_resend_to_a_person():
    [finding] = cors_reflection_rule(_origin_tx())
    assert "허용 목록 일치로 되돌린 정상 응답과 임의 출처 반사를 이 트랜잭션만으로는 구분할 수 없다" in finding.limitations
    assert {"마스킹된 Origin·ACAO는 보지 않는다", "중복 헤더는 판정하지 않는다", "단일 트랜잭션 관측"} <= set(finding.limitations)
    assert "사람이 Burp에서" in finding.next_steps[0].action


def test_hypothesis_of_the_origin_rule_does_not_carry_the_origin_value():
    [finding] = cors_reflection_rule(_origin_tx())
    assert ORIGIN not in finding.hypothesis and not any(ORIGIN in e.observation for e in finding.evidence)


def test_null_origin_reflection_fires():
    assert len(cors_reflection_rule(_origin_tx([("Origin", "null")], [(ACAO, "null"), (ACAC, "true")]))) == 1


@pytest.mark.parametrize("req, resp", [
    ([("ORIGIN", ORIGIN)], [(ACAO.upper(), ORIGIN), (ACAC.lower(), "true")]),
    ([("Origin", f"  {ORIGIN} ")], [(ACAO, f" {ORIGIN}  "), (ACAC, " true ")]),
], ids=["name_case", "value_trim"])
def test_header_name_case_and_outer_whitespace_do_not_matter_for_the_origin_rule(req, resp):
    tx = _origin_tx(req, resp)
    [finding] = cors_reflection_rule(tx)
    assert all(output_gate.resolves(e.pointer, tx) for e in finding.evidence)


@pytest.mark.parametrize("req, resp", [
    ([], [(ACAO, ORIGIN), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, "*"), (ACAC, "true")]),
    ([("Origin", "*")], [(ACAO, "*"), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, "https://b.example"), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN.upper()), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN)]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, "True")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, "false")]),
    ([("Origin", ORIGIN), ("origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAO, ORIGIN), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, "true"), (ACAC, "true")]),
    ([("Origin", MASKED)], [(ACAO, ORIGIN), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, MASKED), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, MASKED)]),
    ([("Origin", MASKED)], [(ACAO, MASKED), (ACAC, "true")]),
    ([("Origin", "")], [(ACAO, ""), (ACAC, "true")]),
    ([("Origin", "  ")], [(ACAO, " "), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, ""), (ACAC, "true")]),
], ids=["no_origin", "no_acao", "wildcard_acao", "wildcard_origin", "values_differ", "case_only_differs", "no_acac",
        "acac_capitalized", "acac_false", "duplicate_origin", "duplicate_acao", "duplicate_acac", "masked_origin",
        "masked_acao", "masked_acac", "both_masked", "both_empty", "both_blank", "empty_acao"])
def test_other_origin_combinations_do_not_fire(req, resp):
    assert cors_reflection_rule(_origin_tx(req, resp)) == []


@pytest.mark.parametrize("req, resp", [
    ([("Origin", ORIGIN)], [(ACAO, ORIGIN), (ACAC, "true")]),
    ([("Origin", ORIGIN)], [(ACAO, "*"), (ACAC, "true")]),
    ([("Origin", "*")], [(ACAO, "*"), (ACAC, "true")]),
], ids=["reflected", "wildcard", "wildcard_origin"])
def test_wildcard_and_origin_rules_never_fire_together(req, resp):
    tx = _origin_tx(req, resp)
    assert len(cors_rule(tx)) + len(cors_reflection_rule(tx)) == 1
    assert len([d for d in evaluate(tx) if d.category == "security_misconfig"]) == 1


# ── 깊은 중첩: 파싱 실패가 ④를 죽이지 않는다 ───────────────────────

def test_deeply_nested_json_body_is_read_as_text_without_crashing():
    content = "[" * 100_000 + "]" * 100_000
    assert evaluate(_tx([_q(PAYLOAD)], body=_body(content))) == []
