"""④ rule-only 결선 — (A) §2.5, §3.0, §3.5 `completed_via_gate`(현존 경로 한정). '위조 거부'로 증명한다.

- 정적: AnalysisResult·ExecutionResponse는 src/sentinel에서 각각 한 곳에서만 만들어진다(심은 우회 전부 거부).
- 동적: ④의 result는 게이트 반환값뿐이고, 규칙이 잘못된 초안을 내면 output_rejected다.
- produced_by는 경로 상수다. 초안·규칙 결과 어디서도 받지 않는다(주입 → 거부).
- 중복 처리는 전체 검증 뒤다: 무효 초안이 병합으로 숨지 않는다.
- 게이트 반환값은 불변이다(frozen + tuple + 깊은 읽기 전용 맵).
- 불변식 위조: completed ⇔ result ≠ null / rule_only ⇔ model_id·prompt_version null.

S v1 확인은 측정이 아니라 동작 확인이다((A) §6.2 — S v1은 규칙에 대해 오염된 스모크 집합).
"""
from __future__ import annotations

import ast
import json
import logging
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import BaseModel, ValidationError

import sentinel
from sentinel.common_types import TextBodyPointer
from sentinel.output_schema import AnalysisMeta, AnalysisResult, FindingDraft
from sentinel.pipeline import execution, output_gate, rule_engine, schema_gate
from sentinel.schema import ExecutionResponse
from sentinel.server.app import create_app
from tools.completed_path import construction_violations
from tools.eval.harness import PredictionRun, RunMeta
from tools.mutation_guard import assert_loaded_from, copy_with_mutation
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_rule_engine import PAYLOAD, REF, _body, _q, _tx
from tests.test_schema import _env, _raw

REPO_ROOT = Path(__file__).resolve().parents[1]
S_V1 = REPO_ROOT / "datasets" / "S" / "v1" / "envelopes"
TX = _tx([_q(PAYLOAD)], [("X-Dummy", "a")], _body(json.dumps({"v": PAYLOAD})))
ENVELOPE = schema_gate.parse_envelope(_raw(_env()))
FAKE_REF = str(uuid.UUID("00000000-0000-4000-8000-0000000000e5"))
HEADER_PTR = {"locus": "resp_header", "name": "x-dummy"}


def _envelope_with(tx) -> object:
    return type(ENVELOPE).model_construct(schema_version="1.0", analysis_type="single", transactions=[tx])


def _json(sent) -> dict:
    return json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


def _meta(**over) -> AnalysisMeta:
    return AnalysisMeta(**{"model_id": None, "policy_version": "p", "prompt_version": None, "ruleset_version": "r",
                           "elapsed_ms": 0, "pipeline_mode": "rule_only", "manifest_snapshot": {}, **over})


def _finding(*pointers, category="info_exposure", ref=str(REF), **over) -> dict:
    return {"category": category, "hypothesis": "h", "claim_basis": "observed", "limitations": [], "next_steps": [],
            "evidence": [{"transaction_ref": ref, "pointer": p, "observation": "o"} for p in pointers], **over}


class _RawDraft:
    """규칙이 낸 초안의 자리에 임의 JSON 구조를 놓는다 — 타입 생성자를 지나지 않은 '잘못된 초안'."""

    def __init__(self, doc: dict) -> None:
        self.doc = doc

    def model_dump(self, mode: str) -> dict:
        return self.doc


def _with_rule_output(monkeypatch, *docs) -> None:
    monkeypatch.setattr(rule_engine, "evaluate", lambda tx: [_RawDraft(d) for d in docs])


def _gate(*findings, advisories=(), txs=(TX,)):
    draft = json.dumps({"findings": list(findings), "advisory_signals": list(advisories)})
    return output_gate.validate_draft(draft, transactions=txs, produced_by="rule", analysis_meta=_meta())


# ── 정적: 생성 지점은 한 곳뿐 ──────────────────────────────────────

def test_result_and_response_are_built_at_exactly_one_place_each():
    assert construction_violations(Path(sentinel.__file__).parent) == []


PLANTS = {
    "result_ctor_elsewhere": "from sentinel.output_schema import AnalysisResult\nr = AnalysisResult()\n",
    "result_validate": "from sentinel.output_schema import AnalysisResult\nr = AnalysisResult.model_validate({})\n",
    "result_validate_json": "from sentinel.output_schema import AnalysisResult\nr = AnalysisResult.model_validate_json('{}')\n",
    "result_type_adapter": "from pydantic import TypeAdapter\nfrom sentinel.output_schema import AnalysisResult\n"
                           "r = TypeAdapter(AnalysisResult)\n",
    "result_alias_assign": "from sentinel.output_schema import AnalysisResult\nA = AnalysisResult\n",
    "result_alias_import": "from sentinel.output_schema import AnalysisResult as A\n",
    "result_subclass": "from sentinel.output_schema import AnalysisResult\nclass A(AnalysisResult):\n    pass\n",
    "result_module_attribute": "import sentinel.output_schema as o\nr = o.AnalysisResult()\n",
    "result_string_name": "import sentinel.output_schema as o\nr = getattr(o, 'AnalysisResult')\n",
    "model_construct": "def f(x):\n    return x.model_construct()\n",
    "construct": "def f(x):\n    return x.construct()\n",
    "parse_obj": "def f(x):\n    return x.parse_obj({})\n",
    "parse_raw": "def f(x):\n    return x.parse_raw('{}')\n",
    "model_copy": "def f(result):\n    return result.model_copy(update={'findings': ()})\n",
    "copy": "def f(result):\n    return result.copy(update={'findings': ()})\n",
    "copy_on_a_local_named_copy": "def f(copy):\n    return copy.copy(update={'findings': ()})\n",
    "dunder_class": "def f(result):\n    return result.__class__\n",
    "type_of_instance": "def f(result):\n    return type(result)(**{})\n",
    "gate_skipped_attribute": "from sentinel.pipeline import output_gate\nr = output_gate._assign(1, 2, 3, 4)\n",
    "gate_skipped_import": "from sentinel.pipeline.output_gate import _assign\nr = _assign(1, 2, 3, 4)\n",
    "response_ctor_elsewhere": "from sentinel.schema import ExecutionResponse\nr = ExecutionResponse()\n",
    "response_validate": "from sentinel.schema import ExecutionResponse\nr = ExecutionResponse.model_validate({})\n",
}


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "sentinel"
    shutil.copytree(Path(sentinel.__file__).parent, root, ignore=shutil.ignore_patterns("__pycache__"))
    return root


@pytest.mark.parametrize("name", sorted(PLANTS))
def test_planted_construction_path_is_found(tree, name):
    (tree / "pipeline" / "planted.py").write_text(PLANTS[name], encoding="utf-8")
    found = construction_violations(tree)
    assert found and all("planted.py" in v for v in found)


def test_second_build_inside_the_allowed_function_is_found(tree):
    path = tree / "pipeline" / "execution.py"
    source = path.read_text(encoding="utf-8")
    path.write_text(source + "\n\ndef build_execution_response():\n    return ExecutionResponse()\n", encoding="utf-8")
    assert "build_count:ExecutionResponse=2" in construction_violations(tree)


def test_removed_gate_build_is_found(tree):
    path = tree / "pipeline" / "output_gate.py"
    source = path.read_text(encoding="utf-8")
    assert "    return AnalysisResult(" in source
    path.write_text(source.replace("    return AnalysisResult(", "    return dict("), encoding="utf-8")
    assert "build_count:AnalysisResult=0" in construction_violations(tree)


@pytest.mark.parametrize("source", [
    "from sentinel.output_schema import AnalysisResult\ndef f(x: AnalysisResult) -> AnalysisResult:\n    return x\n",
    "from sentinel.output_schema import AnalysisResult\nx: AnalysisResult | None = None\n",
    "import copy\ndef f(x):\n    return copy.deepcopy(x)\n",
], ids=["annotation", "variable_annotation", "deepcopy"])
def test_type_annotations_and_deepcopy_are_not_construction_paths(tree, source):
    (tree / "pipeline" / "planted.py").write_text(source, encoding="utf-8")
    assert construction_violations(tree) == []


# ── 동적: ④는 게이트를 지난다 ──────────────────────────────────────

def test_completed_result_is_the_object_the_gate_returned(monkeypatch):
    real, returned = output_gate.validate_draft, []
    monkeypatch.setattr(output_gate, "validate_draft", lambda *a, **k: returned.append(real(*a, **k)) or returned[-1])
    response = execution.build_execution_response(ENVELOPE, {})
    assert response.analysis_status == "completed" and len(returned) == 1 and response.result is returned[0]


def test_gate_rejection_overrides_a_rule_finding(monkeypatch):
    monkeypatch.setattr(output_gate, "validate_draft", lambda *a, **k: output_gate.OutputRejection(("draft_unparseable",)))
    response = execution.build_execution_response(_envelope_with(TX), {})
    assert response.analysis_status == "output_rejected" and response.result is None


def test_rule_draft_with_no_evidence_is_output_rejected_and_audited(monkeypatch, caplog):
    _with_rule_output(monkeypatch, _finding())
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        response = execution.build_execution_response(_envelope_with(TX), {})
    assert response.analysis_status == "output_rejected" and response.result is None
    assert any("evidence_missing" in r.getMessage() for r in caplog.records if r.name == "sentinel.audit")


def test_rule_draft_with_an_unresolvable_locator_is_output_rejected_and_audited(monkeypatch, caplog):
    _with_rule_output(monkeypatch, _finding({"locus": "resp_header", "name": "x-missing"}))
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        response = execution.build_execution_response(_envelope_with(TX), {})
    assert response.analysis_status == "output_rejected" and response.result is None
    assert any("pointer_unresolvable" in r.getMessage() for r in caplog.records if r.name == "sentinel.audit")


def test_rule_draft_pointing_outside_analyzed_refs_is_output_rejected(monkeypatch):
    _with_rule_output(monkeypatch, _finding(HEADER_PTR, ref=FAKE_REF))
    assert execution.build_execution_response(_envelope_with(TX), {}).analysis_status == "output_rejected"


def test_output_rejected_reaches_the_client_as_a_200_with_null_result(token, monkeypatch):
    _with_rule_output(monkeypatch, _finding())
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    body = _json(sent)
    assert _status(sent) == 200 and body["analysis_status"] == "output_rejected" and body["result"] is None


def test_clean_input_is_completed_with_empty_findings_not_a_missing_result(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    body = _json(sent)
    assert body["analysis_status"] == "completed" and body["result"]["findings"] == []
    assert body["skipped_reasons"] == ["llm_analysis_not_implemented"]


def test_rule_only_meta_carries_no_invented_model_or_prompt_value(token):
    meta = _json(_drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))[0])["result"]["analysis_meta"]
    assert meta["pipeline_mode"] == "rule_only" and meta["model_id"] is None and meta["prompt_version"] is None
    assert meta["ruleset_version"] == rule_engine.RULESET_VERSION


def test_response_is_not_stored_or_sent_anywhere_by_the_stage():
    source = Path(execution.__file__).read_text(encoding="utf-8")
    assert not [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open"]


# ── produced_by: 경로 상수 ─────────────────────────────────────────

def test_gate_call_takes_produced_by_from_the_path_constant():
    tree = ast.parse(Path(execution.__file__).read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "validate_draft"]
    assert len(calls) == 1
    [arg] = [k.value for k in calls[0].keywords if k.arg == "produced_by"]
    assert isinstance(arg, ast.Name) and arg.id == "RULE_PATH" and execution.RULE_PATH == "rule"


def test_every_finding_of_the_rule_path_is_marked_rule():
    result = execution.build_execution_response(_envelope_with(TX), {}).result
    assert result.findings and {f.produced_by for f in result.findings} == {"rule"}


@pytest.mark.parametrize("value", ["llm", "hybrid", "rule"])
def test_produced_by_inside_a_rule_draft_is_rejected_even_when_it_says_rule(monkeypatch, caplog, value):
    _with_rule_output(monkeypatch, _finding(HEADER_PTR, produced_by=value))
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        response = execution.build_execution_response(_envelope_with(TX), {})
    assert response.analysis_status == "output_rejected"
    assert any("server_field_injected" in r.getMessage() for r in caplog.records if r.name == "sentinel.audit")


def test_draft_type_has_no_produced_by_field():
    assert "produced_by" not in FindingDraft.model_fields


# ── 중복 처리: 전체 검증 뒤 ────────────────────────────────────────

OUT_OF_RANGE = {**HEADER_PTR, "range": {"start": 0, "end": 99}}  # range는 CNA에 없다 → HEADER_PTR와 CNA가 같다


@pytest.mark.parametrize("order", [(HEADER_PTR, OUT_OF_RANGE), (OUT_OF_RANGE, HEADER_PTR)], ids=["bad_last", "bad_first"])
def test_invalid_twin_of_a_duplicate_is_not_hidden_by_the_merge(order):
    """같은 CNA의 두 초안 중 하나만 해석 불가 → 병합이 숨기지 못하고 전체 폐기된다(§2.4)."""
    result = _gate(*(_finding(p) for p in order))
    assert isinstance(result, output_gate.OutputRejection) and result.reason_codes == ("pointer_unresolvable",)


def test_exact_duplicates_merge_into_the_first_draft():
    result = _gate(_finding(HEADER_PTR, hypothesis="first"), _finding({**HEADER_PTR, "name": "X-DUMMY"}, hypothesis="second"))
    assert [f.hypothesis for f in result.findings] == ["first"]


def test_different_locators_with_the_same_cna_merge():
    json_node = {"locus": "resp_body", "body": {"kind": "json", "path": "/v"}}
    text_range = {"locus": "resp_body", "body": {"kind": "text", "range": {"start": 7, "end": 9}}}
    assert len(_gate(_finding(json_node), _finding(text_range)).findings) == 1


def test_overlapping_evidence_sets_do_not_merge():
    status = {"locus": "resp_status"}
    assert len(_gate(_finding(HEADER_PTR), _finding(HEADER_PTR, status)).findings) == 2


def test_same_cna_with_another_category_does_not_merge():
    assert len(_gate(_finding(HEADER_PTR), _finding(HEADER_PTR, category="access_control")).findings) == 2


def _advisory(*pointers) -> dict:
    return {"type": "out_of_scope_advisory", "topic": "t", "suggestion": "s",
            "basis": [{"transaction_ref": str(REF), "pointer": p, "observation": "o"} for p in pointers]}


def test_advisory_with_the_cna_set_of_a_finding_is_dropped():
    assert _gate(_finding(HEADER_PTR), advisories=[_advisory(HEADER_PTR)]).advisory_signals == ()


def test_advisory_with_another_cna_set_is_kept():
    result = _gate(_finding(HEADER_PTR), advisories=[_advisory(HEADER_PTR, {"locus": "resp_status"}), _advisory()])
    assert len(result.advisory_signals) == 2


# ── 게이트 이후 변경 차단 ──────────────────────────────────────────

def _result() -> AnalysisResult:
    return _gate(_finding(HEADER_PTR, next_steps=[{"type": "verification", "action": "a", "rationale": "r"}],
                          limitations=["l"]))


def test_gate_result_rejects_field_assignment():
    with pytest.raises(ValidationError):
        _result().findings = ()


def test_finding_inside_a_gate_result_rejects_field_assignment():
    with pytest.raises(ValidationError):
        _result().findings[0].status = "confirmed"


def test_evidence_inside_a_gate_result_rejects_field_assignment():
    with pytest.raises(ValidationError):
        _result().findings[0].evidence[0].corroboration = "matched"


@pytest.mark.parametrize("get", [lambda r: r.findings, lambda r: r.analyzed_refs, lambda r: r.advisory_signals,
                                 lambda r: r.findings[0].evidence, lambda r: r.findings[0].limitations,
                                 lambda r: r.findings[0].next_steps, lambda r: r.findings[0].evidence[0].anomaly_flags],
                         ids=["findings", "analyzed_refs", "advisory_signals", "evidence", "limitations", "next_steps",
                              "anomaly_flags"])
def test_list_fields_of_a_gate_result_cannot_be_changed_in_place(get):
    with pytest.raises(AttributeError):
        get(_result()).append(None)


SNAPSHOT = {"capabilities": {"k": {"status": "enforced", "nodes": ["a", {"n": 1}]}}, "version": 1}
USAGE = {"prompt": 1}


def _meta_of_a_gate_result():
    meta = _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", token_usage=dict(USAGE),
                 manifest_snapshot=json.loads(json.dumps(SNAPSHOT)))
    draft = json.dumps({"findings": [], "advisory_signals": []})
    return output_gate.validate_draft(draft, transactions=(TX,), produced_by="llm", analysis_meta=meta).analysis_meta


def _set_top(m):
    m.manifest_snapshot["version"] = 2


def _add_top(m):
    m.manifest_snapshot["new"] = 1


def _del_top(m):
    del m.manifest_snapshot["version"]


def _set_nested(m):
    m.manifest_snapshot["capabilities"]["k"]["status"] = "tampered"


def _set_inside_a_list(m):
    m.manifest_snapshot["capabilities"]["k"]["nodes"][1]["n"] = 2


def _set_usage(m):
    m.token_usage["prompt"] = 0


@pytest.mark.parametrize("change", [_set_top, _add_top, _del_top, _set_nested, _set_inside_a_list, _set_usage],
                         ids=lambda f: f.__name__.strip("_"))
def test_map_fields_of_a_gate_result_cannot_be_changed_by_item(change):
    with pytest.raises(TypeError):
        change(_meta_of_a_gate_result())


@pytest.mark.parametrize("change", [lambda m: m.manifest_snapshot.update(x=1), lambda m: m.manifest_snapshot.pop("version"),
                                    lambda m: m.manifest_snapshot.clear(), lambda m: m.token_usage.update(x=1),
                                    lambda m: m.manifest_snapshot["capabilities"]["k"]["nodes"].append("x")],
                         ids=["update", "pop", "clear", "usage_update", "list_append"])
def test_map_fields_of_a_gate_result_have_no_mutating_methods(change):
    with pytest.raises(AttributeError):
        change(_meta_of_a_gate_result())


def test_changing_the_source_map_does_not_reach_the_result():
    source = json.loads(json.dumps(SNAPSHOT))
    meta = _meta(manifest_snapshot=source)
    source["capabilities"]["k"]["status"] = "tampered"
    assert meta.manifest_snapshot["capabilities"]["k"]["status"] == "enforced"


def test_real_stage_four_result_has_a_read_only_snapshot_too():
    result = execution.build_execution_response(_envelope_with(TX), json.loads(json.dumps(SNAPSHOT))).result
    with pytest.raises(TypeError):
        result.analysis_meta.manifest_snapshot["capabilities"]["k"]["status"] = "tampered"


def _mutable_values(value) -> list:
    """모델 필드·맵·튜플을 따라 내려가며 찾은 가변 컨테이너."""
    if isinstance(value, BaseModel):
        return [m for name in type(value).model_fields for m in _mutable_values(getattr(value, name))]
    if isinstance(value, (list, dict, set, bytearray)):
        return [value]
    if isinstance(value, MappingProxyType):
        return [m for v in value.values() for m in _mutable_values(v)]
    if isinstance(value, tuple):
        return [m for v in value for m in _mutable_values(v)]
    return []


def test_no_mutable_container_is_reachable_from_a_gate_result():
    meta = _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", token_usage=dict(USAGE),
                 manifest_snapshot=json.loads(json.dumps(SNAPSHOT)))
    draft = json.dumps({"findings": [_finding(HEADER_PTR, limitations=["l"])],
                        "advisory_signals": [_advisory({"locus": "resp_status"})]})
    result = output_gate.validate_draft(draft, transactions=(TX,), produced_by="llm", analysis_meta=meta)
    assert result.findings and result.advisory_signals and _mutable_values(result) == []


@pytest.mark.parametrize("value", [{"a": {1, 2}}, {"a": bytearray(b"x")}, {"a": object()}], ids=["set", "bytearray", "object"])
def test_snapshot_refuses_values_that_are_not_json(value):
    with pytest.raises(ValidationError):
        _meta(manifest_snapshot=value)


def test_read_only_maps_serialize_as_plain_json_objects_and_arrays():
    dumped = _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", token_usage=dict(USAGE),
                   manifest_snapshot=json.loads(json.dumps(SNAPSHOT))).model_dump(mode="json")
    assert dumped["manifest_snapshot"] == SNAPSHOT and dumped["token_usage"] == USAGE
    assert type(dumped["manifest_snapshot"]) is dict and json.dumps(dumped)


def test_result_json_keeps_arrays_for_list_fields():
    dumped = _result().model_dump(mode="json")
    assert isinstance(dumped["findings"], list) and isinstance(dumped["findings"][0]["evidence"], list)
    assert isinstance(dumped["analyzed_refs"], list) and dumped["advisory_signals"] == []


# ── ③: 깊은 중첩 본문은 500이 아니라 거부 + 감사 ───────────────────

def test_deeply_nested_body_with_a_json_span_is_rejected_and_audited_at_stage_three_not_a_500(token, caplog):
    deep = "[" * 100_000 + "]" * 100_000
    env = _env()
    env["transactions"][0]["response"]["body"].update(
        content=deep, size_bytes=len(deep), content_type="application/json", encoding="utf8", truncated=False,
        masked_spans=[{"at": {"kind": "json", "path": "/0"}, "ref": {"masked": True, "label": None, "kind": "token"}}])
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(env))
    assert _status(sent) == 422 and _json(sent) == {"error": "sanitization_rejected"}
    assert any("masked_span_json_unparseable" in r.getMessage() for r in caplog.records if r.name == "sentinel.audit")


# ── 불변식 위조 ────────────────────────────────────────────────────

def _response(**over) -> dict:
    return {"analysis_status": "completed", "skipped_reasons": ["x"], "manifest_snapshot": {}, "result": _result(), **over}


def test_valid_status_and_result_pairs_pass():
    assert ExecutionResponse(**_response()).result is not None
    for status in ("not_implemented", "output_rejected"):
        assert ExecutionResponse(**_response(analysis_status=status, result=None)).result is None


@pytest.mark.parametrize("over", [{"result": None},
                                  {"analysis_status": "not_implemented"},
                                  {"analysis_status": "output_rejected"}],
                         ids=["completed_without_result", "not_implemented_with_result", "output_rejected_with_result"])
def test_status_and_result_cannot_disagree(over):
    with pytest.raises(ValidationError):
        ExecutionResponse(**_response(**over))


def test_result_field_cannot_be_left_out():
    doc = _response(analysis_status="not_implemented")
    del doc["result"]
    with pytest.raises(ValidationError):
        ExecutionResponse(**doc)


BAD_METAS = {
    "rule_llm_null_model": {"pipeline_mode": "rule_llm", "prompt_version": "v"},
    "rule_llm_null_prompt": {"pipeline_mode": "rule_llm", "model_id": "m"},
    "rule_llm_both_null": {"pipeline_mode": "rule_llm"},
    "rule_only_with_model": {"model_id": "m"},
    "rule_only_with_prompt": {"prompt_version": "v"},
    "rule_llm_empty_model": {"pipeline_mode": "rule_llm", "model_id": "", "prompt_version": "v"},
    "unknown_mode": {"pipeline_mode": "llm_only"},
}


def test_valid_meta_pairs_pass():
    assert _meta().model_id is None
    assert _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v").model_id == "m"


@pytest.mark.parametrize("name", sorted(BAD_METAS))
def test_analysis_meta_cannot_invent_or_omit_producer_versions(name):
    with pytest.raises(ValidationError):
        _meta(**BAD_METAS[name])


# ── 하네스 메타 ────────────────────────────────────────────────────

def _run_meta(**over) -> RunMeta:
    return RunMeta(**{"split": "dev", "pipeline_mode": "rule_only", "model_id": None, "prompt_version": None,
                      "ruleset_version": "r", **over})


@pytest.mark.parametrize("over", [{"model_id": "m"}, {"prompt_version": "v"}, {"pipeline_mode": "rule_llm"},
                                  {"pipeline_mode": "other"}],
                         ids=["rule_only_with_model", "rule_only_with_prompt", "rule_llm_null", "unknown_mode"])
def test_run_meta_follows_the_same_rule(over):
    with pytest.raises(ValidationError):
        _run_meta(**over)


def test_run_meta_header_keeps_json_null_next_to_the_pipeline_mode():
    run = PredictionRun(run_meta=_run_meta(), results={})
    doc = json.loads(run.model_dump_json())["run_meta"]
    assert doc["pipeline_mode"] == "rule_only" and doc["model_id"] is None and doc["prompt_version"] is None


# ── S v1 동작 확인(측정 아님) ──────────────────────────────────────

S_V1_EXPECTED = {
    "0d851bfd-db38-46eb-ad00-1501b42137ed": [("reflected_injection_indicator", {"/query"})],
    "d603e430-7c16-4075-8637-d3ccceeb5c7c": [("info_exposure", {"/error/stack"})],
    "84547b2f-4eab-47f2-b190-66d9ef47a3c5": [("security_misconfig", set())],
    "e6f3ed03-2de5-4fa1-87d9-5ba58cdaf51a": [],  # hard negative: 이스케이프된 반사
    "fab71ff6-1f53-4306-959e-6039927ea4c2": [],  # IDOR — 규칙 범위 밖
    "91640ac7-d590-45cc-8b2f-c207ec3301ed": [],  # clean
}


def test_expected_table_covers_every_s_v1_envelope():
    assert {p.stem for p in S_V1.glob("*.json")} == set(S_V1_EXPECTED)


@pytest.mark.parametrize("ref", sorted(S_V1_EXPECTED))
def test_s_v1_envelope_through_the_real_stages_matches_the_table(token, ref):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), (S_V1 / f"{ref}.json").read_bytes())
    body = _json(sent)
    assert _status(sent) == 200 and body["analysis_status"] == "completed"
    seen = [(f["category"], {e["pointer"]["body"]["path"] for e in f["evidence"] if e["pointer"]["locus"] == "resp_body"})
            for f in body["result"]["findings"]]
    assert seen == S_V1_EXPECTED[ref]


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "rule_wiring_probe"
_DRIVER = """
import importlib, os, sys, pytest
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]
importlib.import_module(sys.argv[1])  # pytest의 pythonpath 삽입 전에 변이본을 먼저 적재
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_W = "tests/test_rule_wiring.py::"
_E = "tests/test_rule_engine.py::"
GATE_CALL = ("    outcome = output_gate.validate_draft(draft, transactions=transactions, produced_by=RULE_PATH,\n"
             "                                         analysis_meta=_analysis_meta(manifest_snapshot, started))\n")
SRC_MUTATIONS = {
    "gate_bypassed": ("sentinel/pipeline/execution.py", "sentinel.pipeline.execution", GATE_CALL,
                      "    outcome = output_gate._assign(output_gate.AnalysisDraft.model_validate_json(draft), "
                      "tuple(t.meta.transaction_id for t in transactions), RULE_PATH, "
                      "_analysis_meta(manifest_snapshot, started))\n",
                      [_W + "test_rule_draft_with_an_unresolvable_locator_is_output_rejected_and_audited",
                       _W + "test_result_and_response_are_built_at_exactly_one_place_each"]),
    "produced_by_not_the_constant": ("sentinel/pipeline/execution.py", "sentinel.pipeline.execution",
                                     "produced_by=RULE_PATH,", 'produced_by="llm",',
                                     [_W + "test_gate_call_takes_produced_by_from_the_path_constant",
                                      _W + "test_every_finding_of_the_rule_path_is_marked_rule"]),
    "merge_before_validation": ("sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate",
                                "    outside = _refs_outside(parsed, frozenset(by_id))  # ④\n",
                                "    parsed = AnalysisDraft(findings=list({f.category: f for f in reversed(parsed.findings)}"
                                ".values()), advisory_signals=parsed.advisory_signals)\n"
                                "    outside = _refs_outside(parsed, frozenset(by_id))  # ④\n",
                                [_W + "test_invalid_twin_of_a_duplicate_is_not_hidden_by_the_merge[bad_last]"]),
    "no_merge": ("sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate",
                 "return _assign(_merged(parsed, by_id), tuple(by_id),", "return _assign(parsed, tuple(by_id),",
                 [_W + "test_exact_duplicates_merge_into_the_first_draft",
                  _W + "test_advisory_with_the_cna_set_of_a_finding_is_dropped"]),
    "stored_not_frozen": ("sentinel/output_schema.py", "sentinel.output_schema",
                          'class _Stored(BaseModel):\n    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)',
                          'class _Stored(BaseModel):\n    model_config = ConfigDict(strict=True, extra="forbid")',
                          [_W + "test_gate_result_rejects_field_assignment",
                           _W + "test_finding_inside_a_gate_result_rejects_field_assignment",
                           _W + "test_evidence_inside_a_gate_result_rejects_field_assignment"]),
    "maps_not_frozen": ("sentinel/output_schema.py", "sentinel.output_schema",
                        "        return MappingProxyType({k: _deep_frozen(v) for k, v in value.items()})\n",
                        "        return {k: _deep_frozen(v) for k, v in value.items()}\n",
                        [_W + "test_map_fields_of_a_gate_result_cannot_be_changed_by_item[set_top]",
                         _W + "test_map_fields_of_a_gate_result_cannot_be_changed_by_item[set_usage]",
                         _W + "test_real_stage_four_result_has_a_read_only_snapshot_too",
                         _W + "test_no_mutable_container_is_reachable_from_a_gate_result"]),
    "maps_frozen_only_at_the_top": ("sentinel/output_schema.py", "sentinel.output_schema",
                                    "        return MappingProxyType({k: _deep_frozen(v) for k, v in value.items()})\n",
                                    "        return MappingProxyType(value)\n",
                                    [_W + "test_map_fields_of_a_gate_result_cannot_be_changed_by_item[set_nested]",
                                     _W + "test_changing_the_source_map_does_not_reach_the_result",
                                     _W + "test_no_mutable_container_is_reachable_from_a_gate_result"]),
    "arrays_in_maps_stay_lists": ("sentinel/output_schema.py", "sentinel.output_schema",
                                  "        return tuple(_deep_frozen(v) for v in value)\n",
                                  "        return [_deep_frozen(v) for v in value]\n",
                                  [_W + "test_map_fields_of_a_gate_result_have_no_mutating_methods[list_append]",
                                   _W + "test_no_mutable_container_is_reachable_from_a_gate_result"]),
    "status_result_invariant_off": ("sentinel/schema.py", "sentinel.schema",
                                    '        if (self.analysis_status == "completed") != (self.result is not None):\n',
                                    "        if False:\n",
                                    [_W + "test_status_and_result_cannot_disagree[completed_without_result]",
                                     _W + "test_status_and_result_cannot_disagree[not_implemented_with_result]",
                                     _W + "test_status_and_result_cannot_disagree[output_rejected_with_result]"]),
    "producer_version_rule_off": ("sentinel/output_schema.py", "sentinel.output_schema",
                                  '    if pipeline_mode == "rule_only":\n        return model_id is None and prompt_version is None\n'
                                  "    return model_id is not None and prompt_version is not None\n",
                                  "    return True\n",
                                  [_W + "test_analysis_meta_cannot_invent_or_omit_producer_versions[rule_llm_both_null]",
                                   _W + "test_analysis_meta_cannot_invent_or_omit_producer_versions[rule_only_with_model]",
                                   _W + "test_run_meta_follows_the_same_rule[rule_only_with_model]"]),
    "first_node_not_in_cna_order": ("sentinel/pipeline/rule_engine.py", "sentinel.pipeline.rule_engine",
                                    "    return sorted(nodes, key=lambda n: cna_sort_key(canonical_address("
                                    'tx, _body_at(JsonBodyPointer(kind="json", path=n[0])))))\n',
                                    "    return nodes\n",
                                    [_E + "test_multi_node_reflection_uses_only_the_first_node_in_cna_order"]),
    "duplicate_cors_header_counts": ("sentinel/pipeline/rule_engine.py", "sentinel.pipeline.rule_engine",
                                     "    if len(values) != 1 or not isinstance(values[0], str):\n",
                                     "    if not values or not isinstance(values[0], str):\n",
                                     [_E + "test_other_header_combinations_do_not_fire[duplicate_acao]",
                                      _E + "test_other_header_combinations_do_not_fire[duplicate_acac_mixed_case]"]),
    "reflection_ignores_masked_skip": ("sentinel/pipeline/rule_engine.py", "sentinel.pipeline.rule_engine",
                                       "        occurrence = seen.get(key, 0)\n        seen[key] = occurrence + 1\n"
                                       "        if not isinstance(param.value, str) or",
                                       "        if not isinstance(param.value, str):\n            continue\n"
                                       "        occurrence = seen.get(key, 0)\n        seen[key] = occurrence + 1\n"
                                       "        if ",
                                       [_E + "test_masked_param_is_skipped_but_still_counts_for_occurrence"]),
    "deep_json_not_a_value_error": ("sentinel/strict_json.py", "sentinel.strict_json",
                                    "    except RecursionError:  # 깊은 중첩은 값 문제다 — 호출자가 ValueError 하나만 다루면 되게 한다\n"
                                    '        raise ValueError("중첩이 너무 깊음") from None\n',
                                    "    except KeyError:\n        raise\n",
                                    [_E + "test_deeply_nested_json_body_is_read_as_text_without_crashing",
                                     _W + "test_deeply_nested_body_with_a_json_span_is_rejected_and_audited_at_stage_three_not_a_500"]),
}
TOOL_MUTATIONS = {
    "static_check_off": ("tools/completed_path.py", "tools.completed_path", "        found += scan.violations\n",
                         "        pass\n",
                         [_W + "test_planted_construction_path_is_found[model_copy]",
                          _W + "test_planted_construction_path_is_found[parse_obj]",
                          _W + "test_planted_construction_path_is_found[result_type_adapter]"]),
    "build_count_off": ("tools/completed_path.py", "tools.completed_path", "if count != 1]", "if False]",
                        [_W + "test_second_build_inside_the_allowed_function_is_found",
                         _W + "test_removed_gate_build_is_found"]),
}


def _run_mutant(paths: list[Path], module: str, nodes: list[str], mutant: Path) -> None:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(p) for p in paths), "PYTHONUTF8": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes], cwd=REPO_ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_each_wiring_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_static_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
