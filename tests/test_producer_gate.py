"""생산자별 게이트·결과 표현 — (A) §2.4, §2.5, §3.5 `producer_gate_merge`·`clean_requires_no_failure`·`prompt_model_freeze`.

합성 초안으로 증명한다. 어댑터는 호출하지 않는다. LLM 초안은 호출자가 넘긴 문자열이거나 LlmFailure다.
"""
from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.audit import attach_audit_store, detach_audit_store
from sentinel.output_schema import LLM_FAILURE_REASONS, AnalysisResult
from sentinel.pipeline import execution, output_gate, rule_engine
from sentinel.pipeline.execution import LlmRun
from sentinel.pipeline.output_gate import LlmFailure, OutputRejection, validate_producers
from sentinel.schema import ExecutionResponse
from tools.eval import harness
from tools.eval.harness import OUT_OF_FREEZE_ORDER, PredictionRun, RunMeta, freeze_order
from tools.dataset.labelfile import LabelFile
from tools.mutation_guard import copy_with_mutation
from tests.test_eval_harness import DATASET, L, _anchor, _correct, _result, _run, _strict
from tests.test_rule_wiring import HEADER_PTR, TX, _envelope_with, _finding, _meta, _run_mutant

REPO_ROOT = Path(__file__).resolve().parents[1]
STATUS = {"locus": "resp_status"}
EMPTY = json.dumps({"findings": [], "advisory_signals": []})


@pytest.fixture(autouse=True)
def _audit_store(tmp_path):
    """rule_llm 경로는 지문을 못 남기면 LLM 결과를 버린다."""
    handler = attach_audit_store(tmp_path / "audit.sqlite3")
    yield
    detach_audit_store(handler)


def _draft(*findings) -> str:
    return json.dumps({"findings": list(findings), "advisory_signals": []})


def _make_meta(llm_outcome):
    return _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", llm_outcome=llm_outcome)


def _gate(rule: str, llm):
    return validate_producers(rule, llm, transactions=(TX,), produced_by="rule", make_meta=_make_meta)


def _respond(llm_output) -> ExecutionResponse:
    return execution.build_execution_response(_envelope_with(TX), {}, LlmRun("m@sha256:x", "p", llm_output, "view", 1))


# ── 생산자 단위 폐기 ───────────────────────────────────────────────

def test_llm_draft_rejected_keeps_the_rule_findings():
    result = _gate(_draft(_finding(HEADER_PTR)), "not json")
    assert isinstance(result, AnalysisResult) and [f.produced_by for f in result.findings] == ["rule"]
    assert result.analysis_meta.llm_outcome == "rejected"


def test_one_invalid_finding_discards_the_whole_llm_draft():
    """부분 수용 금지는 생산자 안에서 그대로다."""
    good, bad = _finding(STATUS), _finding({"locus": "resp_header", "name": "x-missing"})
    result = _gate(EMPTY, _draft(good, bad))
    assert result.findings == () and result.analysis_meta.llm_outcome == "rejected"


def test_rule_draft_rejected_is_output_rejected_even_with_a_good_llm_draft():
    result = _gate("not json", _draft(_finding(HEADER_PTR)))
    assert isinstance(result, OutputRejection)


@pytest.mark.parametrize("reason", LLM_FAILURE_REASONS)
def test_llm_failure_keeps_the_rule_findings_and_records_the_reason(reason):
    result = _gate(_draft(_finding(HEADER_PTR)), LlmFailure(reason))
    assert [f.produced_by for f in result.findings] == ["rule"] and result.analysis_meta.llm_outcome == f"failed:{reason}"


def test_failure_reason_is_a_closed_list():
    with pytest.raises(ValueError):
        LlmFailure("anything")


def test_llm_rejection_is_audited_without_content(caplog):
    marker = secrets.token_hex(8)
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        _gate(EMPTY, f'{{"{marker}": 1}}')
    assert "llm_draft_rejected" in caplog.text and marker not in caplog.text


# ── 주입 ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("field, value", [("produced_by", "rule"), ("status", "confirmed"), ("finding_id", "x")])
def test_server_field_in_an_llm_draft_is_rejected(field, value):
    result = _gate(EMPTY, _draft(_finding(HEADER_PTR, **{field: value})))
    assert result.findings == () and result.analysis_meta.llm_outcome == "rejected"


@pytest.mark.parametrize("pointer", [{**HEADER_PTR, "range": {"start": 0, "end": 1}},
                                     {"locus": "resp_body", "body": {"kind": "json", "path": "/v", "range": {"start": 0, "end": 1}}},
                                     {"locus": "resp_body", "body": {"kind": "text", "range": {"start": 0, "end": 1}}}],
                         ids=["header", "json_body", "text_body"])
def test_range_in_an_llm_draft_is_rejected(pointer, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        result = _gate(EMPTY, _draft(_finding(pointer)))
    assert result.findings == () and result.analysis_meta.llm_outcome == "rejected" and "llm_range_present" in caplog.text


def test_range_in_a_rule_draft_is_allowed():
    pointer = {"locus": "resp_body", "body": {"kind": "text", "range": {"start": 0, "end": 1}}}
    result = validate_producers(_draft(_finding(pointer)), None, transactions=(TX,), produced_by="rule", make_meta=lambda _o: _meta())
    assert len(result.findings) == 1


# ── 병합 ───────────────────────────────────────────────────────────

def test_same_defect_from_both_producers_is_one_hybrid_with_the_rule_wording():
    result = _gate(_draft(_finding(HEADER_PTR, hypothesis="rule")), _draft(_finding(HEADER_PTR, hypothesis="llm")))
    assert [(f.produced_by, f.hypothesis) for f in result.findings] == [("hybrid", "rule")]
    assert result.analysis_meta.llm_outcome == "ok"


def test_same_defect_with_another_locator_form_is_still_hybrid():
    json_node = {"locus": "resp_body", "body": {"kind": "json", "path": "/v"}}
    text_range = {"locus": "resp_body", "body": {"kind": "text", "range": {"start": 7, "end": 9}}}
    assert [f.produced_by for f in _gate(_draft(_finding(text_range)), _draft(_finding(json_node))).findings] == ["hybrid"]


def test_different_defects_stay_apart_with_their_producers():
    result = _gate(_draft(_finding(HEADER_PTR)), _draft(_finding(STATUS)))
    assert [f.produced_by for f in result.findings] == ["rule", "llm"]


def test_overlapping_evidence_does_not_merge_across_producers():
    result = _gate(_draft(_finding(HEADER_PTR)), _draft(_finding(HEADER_PTR, STATUS)))
    assert [f.produced_by for f in result.findings] == ["rule", "llm"]


def test_same_location_with_another_category_does_not_merge():
    result = _gate(_draft(_finding(HEADER_PTR)), _draft(_finding(HEADER_PTR, category="access_control")))
    assert [f.produced_by for f in result.findings] == ["rule", "llm"]


def test_duplicates_inside_the_llm_draft_merge():
    assert [f.produced_by for f in _gate(EMPTY, _draft(_finding(STATUS), _finding(STATUS))).findings] == ["llm"]


def test_llm_advisory_with_the_cna_set_of_a_rule_finding_is_dropped():
    advisory = {"type": "out_of_scope_advisory", "topic": "t", "suggestion": "s",
                "basis": [{"transaction_ref": str(TX.meta.transaction_id), "pointer": HEADER_PTR, "observation": "o"}]}
    llm = json.dumps({"findings": [], "advisory_signals": [advisory]})
    assert _gate(_draft(_finding(HEADER_PTR)), llm).advisory_signals == ()


# ── ④의 표현 ───────────────────────────────────────────────────────

def test_rule_only_response_is_unchanged():
    response = execution.build_execution_response(_envelope_with(TX), {})
    meta = response.result.analysis_meta
    assert response.skipped_reasons == ["llm_analysis_not_implemented"]
    assert (meta.pipeline_mode, meta.model_id, meta.llm_outcome) == ("rule_only", None, None)


def test_rule_llm_success_has_no_skipped_reasons():
    response = _respond(EMPTY)
    meta = response.result.analysis_meta
    assert response.analysis_status == "completed" and response.skipped_reasons == []
    assert (meta.pipeline_mode, meta.model_id, meta.prompt_version, meta.llm_outcome) == ("rule_llm", "m@sha256:x", "p", "ok")


def test_rejected_llm_draft_is_completed_with_the_reason():
    response = _respond("not json")
    assert response.analysis_status == "completed" and response.skipped_reasons == ["llm_rejected"]
    assert response.result.analysis_meta.llm_outcome == "rejected"


@pytest.mark.parametrize("reason", LLM_FAILURE_REASONS)
def test_llm_failure_is_completed_with_the_reason(reason):
    response = _respond(LlmFailure(reason))
    assert response.analysis_status == "completed" and response.skipped_reasons == [f"llm_failed:{reason}"]


def test_rule_bug_in_rule_llm_mode_is_output_rejected(monkeypatch):
    class Broken:
        def model_dump(self, mode):
            return {}

    monkeypatch.setattr(rule_engine, "evaluate", lambda tx: [Broken()])
    response = _respond(EMPTY)
    assert response.analysis_status == "output_rejected" and response.result is None


# ── 깨끗함 ─────────────────────────────────────────────────────────

def _no_rule_findings(monkeypatch) -> None:
    monkeypatch.setattr(rule_engine, "evaluate", lambda tx: [])


def test_rule_only_with_no_findings_is_clean(monkeypatch):
    _no_rule_findings(monkeypatch)
    assert execution.build_execution_response(_envelope_with(TX), {}).is_clean


def test_rule_llm_success_with_no_findings_is_clean(monkeypatch):
    _no_rule_findings(monkeypatch)
    assert _respond(EMPTY).is_clean


@pytest.mark.parametrize("output", [LlmFailure("timeout"), LlmFailure("audit_write"), "not json"], ids=["timeout", "audit", "rejected"])
def test_llm_failure_with_no_findings_is_not_clean(monkeypatch, output):
    _no_rule_findings(monkeypatch)
    response = _respond(output)
    assert response.result.findings == () and not response.is_clean


def test_response_with_findings_is_not_clean():
    assert not _respond(EMPTY).is_clean  # TX는 규칙이 잡는다


def _response(**over) -> dict:
    doc = {"analysis_status": "completed", "skipped_reasons": [], "manifest_snapshot": {},
           "result": _gate(EMPTY, LlmFailure("timeout"))}
    return {**doc, **over}


@pytest.mark.parametrize("skipped", [[], ["llm_rejected"], ["llm_failed:oversize"], ["llm_analysis_not_implemented"]],
                         ids=["hidden", "other_kind", "other_reason", "mode_only"])
def test_failure_outcome_cannot_hide_behind_other_skipped_reasons(skipped):
    with pytest.raises(ValidationError):
        ExecutionResponse(**_response(skipped_reasons=skipped))


def test_failure_reason_cannot_be_claimed_on_a_successful_result():
    with pytest.raises(ValidationError):
        ExecutionResponse(**_response(skipped_reasons=["llm_failed:timeout"], result=_gate(EMPTY, EMPTY)))


@pytest.mark.parametrize("reason", ["x", "llm_failed:other", "llm_failed:", "rule_engine_not_implemented"])
def test_skipped_reasons_are_a_closed_list(reason):
    with pytest.raises(ValidationError):
        ExecutionResponse(analysis_status="output_rejected", skipped_reasons=[reason], manifest_snapshot={}, result=None)


@pytest.mark.parametrize("over", [{"llm_outcome": "ok"}, {"llm_outcome": "failed:timeout"}], ids=["ok", "failed"])
def test_rule_only_meta_cannot_carry_an_llm_outcome(over):
    with pytest.raises(ValidationError):
        _meta(**over)


def test_rule_llm_meta_needs_an_llm_outcome():
    with pytest.raises(ValidationError):
        _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", llm_outcome=None)


@pytest.mark.parametrize("outcome", ["failed", "failed:other", "OK"])
def test_llm_outcome_is_a_closed_list(outcome):
    with pytest.raises(ValidationError):
        _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="v", llm_outcome=outcome)


# ── 하네스 ─────────────────────────────────────────────────────────

def _llm_run(outcomes: dict) -> PredictionRun:
    """라벨 이름 → (findings, llm_outcome)."""
    results = {str(L[name].transaction_ref): _result(findings, outcome) for name, (findings, outcome) in outcomes.items()}
    return PredictionRun.model_validate_json(json.dumps(
        {"run_meta": {"split": None, "pipeline_mode": "rule_llm", "model_id": "fixture", "prompt_version": "v0", "ruleset_version": "r0"},
         "results": results}))


def _labelled_run() -> tuple[PredictionRun, list[str]]:
    names = sorted(L)
    outcomes = {names[0]: ([], "failed:timeout"), names[1]: ([], "failed:timeout"), names[2]: ([], "rejected")}
    outcomes.update({n: ([], "ok") for n in names[3:]})
    return _llm_run(outcomes), names


def test_j2_reports_llm_rejection_and_failure_by_reason():
    run, names = _labelled_run()
    report = harness.score(DATASET, run)
    llm = report["J2"]["llm"]
    assert llm["failed"]["timeout"]["n"] == len(names) and llm["failed"]["timeout"]["interval"] == harness.wilson(2, len(names))["interval"]
    assert llm["rejected"]["interval"] == harness.wilson(1, len(names))["interval"]
    assert llm["failed"]["oversize"]["interval"] == harness.wilson(0, len(names))["interval"]


def test_rule_only_report_has_no_llm_breakdown():
    from tools.eval import runner
    report = runner.run(DATASET, {})
    assert report["J2"]["llm"] is None and report["J3"]["llm_success"] is None and report["J6"]["llm_success"] is None


def test_j3_and_j6_report_the_llm_success_subset():
    run, names = _labelled_run()
    report = harness.score(DATASET, run)
    success = len(names) - 3
    clean = [x for x in LabelFile.model_validate_json((DATASET / "labels.json").read_bytes()).labels if x.label_status == "verified_clean"]
    ok_refs = {str(L[n].transaction_ref) for n in names[3:]}
    expected = sum(str(x.transaction_ref) in ok_refs for x in clean)
    assert report["J3"]["llm_success"]["verified_clean"]["n"] == expected
    subset = report["J6"]["llm_success"]
    positive = [n for n in names[3:] if L[n].label_status == "labeled_positive"]
    assert (subset["tp"], subset["fp"], subset["fn"]) == (0, 0, len(positive)) and success >= 1


def test_j6_subset_leaves_out_the_failed_transactions():
    names = sorted(n for n in L if L[n].label_status == "labeled_positive")
    good, failed = names[0], names[1]
    findings = [dict(_correct()[0], category=L[good].categories[0], evidence=[])]
    findings[0]["evidence"] = [{"transaction_ref": _anchor(good)[0], "pointer": _anchor(good)[1], "observation": "o",
                                "corroboration": "not_run", "anomaly_flags": [], "review_required": True}]
    report = harness.score(DATASET, _llm_run({good: (findings, "ok"), failed: ([], "failed:timeout")}))
    assert (report["J6"]["llm_success"]["tp"], report["J6"]["llm_success"]["fn"]) == (1, 0)
    assert _strict(report)[0] == 1


def _meta_of(prompt="p", model="m", pipeline_mode="rule_llm") -> RunMeta:
    return RunMeta(split="test", pipeline_mode=pipeline_mode, model_id=model, prompt_version=prompt, ruleset_version="rules-2")


class _Recorded:
    class frozen_against:
        ruleset_version = "rules-2"
        ruleset_hash = harness.FROZEN_RULESETS["rules-2"]


def test_frozen_tables_start_empty():
    assert harness.FROZEN_PROMPTS == frozenset() and harness.FROZEN_MODELS == frozenset()


def test_rule_llm_test_split_is_out_of_order_until_prompt_and_model_are_frozen():
    assert freeze_order(_Recorded, _meta_of()) == OUT_OF_FREEZE_ORDER


@pytest.mark.parametrize("prompts, models, expected", [({"p"}, set(), OUT_OF_FREEZE_ORDER), (set(), {"m"}, OUT_OF_FREEZE_ORDER), ({"p"}, {"m"}, None)],
                         ids=["prompt_only", "model_only", "both"])
def test_rule_llm_needs_both_prompt_and_model_frozen(monkeypatch, prompts, models, expected):
    monkeypatch.setattr(harness, "FROZEN_PROMPTS", frozenset(prompts))
    monkeypatch.setattr(harness, "FROZEN_MODELS", frozenset(models))
    assert freeze_order(_Recorded, _meta_of()) == expected


def test_rule_only_does_not_need_the_llm_tables():
    assert freeze_order(_Recorded, _meta_of(None, None, "rule_only")) is None


# ── 변이 확인 ──────────────────────────────────────────────────────

_P = "tests/test_producer_gate.py::"
GATE = ("sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate")
SCHEMA = ("sentinel/schema.py", "sentinel.schema")
OUT = ("sentinel/output_schema.py", "sentinel.output_schema")
EXEC = ("sentinel/pipeline/execution.py", "sentinel.pipeline.execution")
SRC_MUTATIONS = {
    "llm_rejection_fails_everything": (*GATE, '    if isinstance(parsed, OutputRejection):\n        return None, "rejected"\n',
                                       "    if isinstance(parsed, OutputRejection):\n        raise ValueError\n",
                                       [_P + "test_llm_draft_rejected_keeps_the_rule_findings"]),
    "rule_rejection_ignored": (*GATE, "    if isinstance(rule, OutputRejection):\n        return rule\n",
                               '    if isinstance(rule, OutputRejection):\n        rule = AnalysisDraft(findings=[], advisory_signals=[])\n',
                               [_P + "test_rule_draft_rejected_is_output_rejected_even_with_a_good_llm_draft"]),
    "range_check_off": (*GATE, "    if _has_range(parsed):\n", "    if False:\n", [_P + "test_range_in_an_llm_draft_is_rejected[header]"]),
    "no_hybrid": (*GATE, "            tagged[key] = (tagged[key][0], HYBRID)\n", "            pass\n",
                  [_P + "test_same_defect_from_both_producers_is_one_hybrid_with_the_rule_wording"]),
    "llm_wording_wins": (*GATE, "            tagged[key] = (tagged[key][0], HYBRID)\n", "            tagged[key] = (f, HYBRID)\n",
                         [_P + "test_same_defect_from_both_producers_is_one_hybrid_with_the_rule_wording"]),
    "cross_merge_by_overlap": (*GATE, "        if key not in tagged:\n            tagged[key] = (f, LLM_PATH)\n",
                               "        hit = next((k for k in tagged if k[0] == key[0] and k[1] & key[1]), None)\n"
                               "        key = hit or key\n"
                               "        if key not in tagged:\n            tagged[key] = (f, LLM_PATH)\n",
                               [_P + "test_overlapping_evidence_does_not_merge_across_producers"]),
    "clean_ignores_failure": (*SCHEMA, ' and not self.result.findings and not self._failures()\n', " and not self.result.findings\n",
                              [_P + "test_llm_failure_with_no_findings_is_not_clean[timeout]"]),
    "skipped_consistency_off": (*SCHEMA, "        if self.result is not None and self._failures() != _expected_failures(self.result.analysis_meta.llm_outcome):\n",
                                "        if False:\n", [_P + "test_failure_outcome_cannot_hide_behind_other_skipped_reasons[hidden]",
                                                         _P + "test_failure_reason_cannot_be_claimed_on_a_successful_result"]),
    "skipped_list_open": (*SCHEMA, "        if not set(self.skipped_reasons) <= {MODE_SKIPPED, *FAILURE_SKIPPED}:\n", "        if False:\n",
                          [_P + "test_skipped_reasons_are_a_closed_list[x]"]),
    "outcome_mode_rule_off": (*OUT, '        if (self.pipeline_mode == "rule_only") != (self.llm_outcome is None):\n', "        if False:\n",
                              [_P + "test_rule_only_meta_cannot_carry_an_llm_outcome[ok]", _P + "test_rule_llm_meta_needs_an_llm_outcome"]),
    "failure_not_reported": (*EXEC, '    return [f"llm_{llm_outcome}"] if llm_outcome != "ok" else []\n', "    return []\n",
                             [_P + "test_llm_failure_is_completed_with_the_reason[timeout]"]),
}
HARN = ("tools/eval/harness.py", "tools.eval.harness")
TOOL_MUTATIONS = {
    "llm_tables_not_checked": (*HARN, "    return None if same and llm_frozen else OUT_OF_FREEZE_ORDER\n", "    return None if same else OUT_OF_FREEZE_ORDER\n",
                               [_P + "test_rule_llm_test_split_is_out_of_order_until_prompt_and_model_are_frozen"]),
    "one_table_is_enough": (*HARN, "run_meta.prompt_version in FROZEN_PROMPTS and run_meta.model_id in FROZEN_MODELS", "run_meta.prompt_version in FROZEN_PROMPTS or run_meta.model_id in FROZEN_MODELS",
                            [_P + "test_rule_llm_needs_both_prompt_and_model_frozen[prompt_only]"]),
    "subset_is_everything": (*HARN, '    success = {ref for ref, outcome in outcomes.items() if outcome == "ok"}\n', "    success = set(outcomes)\n",
                             [_P + "test_j3_and_j6_report_the_llm_success_subset", _P + "test_j6_subset_leaves_out_the_failed_transactions"]),
}


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_producer_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_harness_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
