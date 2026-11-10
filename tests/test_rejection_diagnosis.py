"""거부 원인 진단 — (A) §2.8 v1.41: LLM 초안 거부 감사에 Pydantic 오류의 위치·종류만. 집계와 정적 대조.

위치 조각은 계약에 정의된 이름과 정수 인덱스만이다. LLM이 지어낸 키·판별값은 `<extra>`로 바뀌어 감사에 남지 않는다.
"""
from __future__ import annotations

import copy
import json
import logging
from pathlib import Path

import pytest

from sentinel.audit import read_audit_events
from sentinel.pipeline import llm_adapter, llm_path, output_gate
from sentinel.pipeline.llm_prompt import TRANSMISSION_SCHEMA
from sentinel.pipeline.output_gate import CONTRACT_NAMES, EXTRA_PIECE, MAX_SITES, LlmFailure
from tests.support import llm_stub
from tests.support.llm_stub import LlmStub
from tests.test_llm_wiring import MODEL, S_V2, SERVING, _completion
from tests.test_rule_wiring import TX, _meta, _run_mutant
from tests.test_sanitization import FAKES
from tools.eval import runner
from tools.eval.harness import rejection_summary
from tools.eval.schema_gap import gaps
from tools.mutation_guard import copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
REF = str(TX.meta.transaction_id)
EMPTY = json.dumps({"findings": [], "advisory_signals": []})
SECRET_KEY = "sk_" + "live_" + "Q9x" * 10  # 비밀값처럼 보이는 키 이름


def _evidence(**over) -> dict:
    return {"transaction_ref": REF, "pointer": {"locus": "resp_status"}, "observation": "o", **over}


def _finding(*evidence) -> dict:
    return {"category": "info_exposure", "hypothesis": "h", "claim_basis": "observed", "limitations": [], "next_steps": [],
            "evidence": list(evidence) or [_evidence()]}


def _llm(draft: dict | str, caplog) -> list[str]:
    raw = draft if isinstance(draft, str) else json.dumps(draft)
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        output_gate.validate_producers(EMPTY, raw, transactions=[TX], produced_by="rule",
                                       make_meta=lambda outcome: _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="p",
                                                                       llm_outcome=outcome))
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("llm_draft_rejected")]


def _sites(message: str) -> set[str]:
    return set(dict(p.split("=", 1) for p in message.split()[1:])["sites"].split(","))


# ── 감사: 위치·종류만 ──────────────────────────────────────────────

def test_rejection_records_the_contract_path_and_the_error_kind(caplog):
    [message] = _llm({"findings": [_finding(_evidence(transaction_ref="not-a-uuid"))], "advisory_signals": []}, caplog)
    assert _sites(message) == {"findings.0.evidence.0.transaction_ref:uuid_parsing"}


def test_branch_error_keeps_the_discriminator_literals(caplog):
    pointer = {"locus": "resp_body", "body": {"kind": "json", "path": "no-slash"}}
    [message] = _llm({"findings": [_finding(_evidence(pointer=pointer))], "advisory_signals": []}, caplog)
    assert _sites(message) == {"findings.0.evidence.0.pointer.resp_body.body.json.path:value_error"}


def test_invented_key_with_a_secret_looking_name_becomes_extra(caplog):
    [message] = _llm({"findings": [_finding(_evidence(**{SECRET_KEY: FAKES["jwt"]}))], "advisory_signals": []}, caplog)
    assert _sites(message) == {f"findings.0.evidence.0.{EXTRA_PIECE}:extra_forbidden"}
    assert SECRET_KEY not in caplog.text and FAKES["jwt"] not in caplog.text


@pytest.mark.parametrize("pattern", sorted(FAKES))
def test_no_secret_shaped_key_reaches_the_audit(caplog, pattern):
    key = FAKES[pattern][:60]
    _llm({"findings": [_finding(_evidence(**{key: "v"}))], "advisory_signals": [], key: 1}, caplog)
    assert key not in caplog.text


def test_unknown_discriminator_value_leaves_only_the_kind(caplog):
    invented = "secret_" + "locus_" + "x7"
    [message] = _llm({"findings": [_finding(_evidence(pointer={"locus": invented}))], "advisory_signals": []}, caplog)
    assert _sites(message) == {"findings.0.evidence.0.pointer:union_tag_invalid"} and invented not in caplog.text


def test_invented_top_level_key_becomes_extra(caplog):
    [message] = _llm({"findings": [], "advisory_signals": [], "note": "x"}, caplog)
    assert _sites(message) == {f"{EXTRA_PIECE}:extra_forbidden"}


def test_values_and_messages_never_reach_the_audit(caplog):
    marker = "zz" + "marker" + "41"
    _llm({"findings": [_finding(_evidence(transaction_ref=marker, observation=marker))], "advisory_signals": []}, caplog)
    assert marker not in caplog.text and "Input should be" not in caplog.text


def test_not_json_has_a_root_site(caplog):
    [message] = _llm("not json", caplog)
    assert _sites(message) == {":json_invalid"}


def test_number_of_sites_is_capped(caplog):
    findings = [_finding(_evidence(transaction_ref=f"bad-{i}")) for i in range(MAX_SITES + 10)]
    [message] = _llm({"findings": findings, "advisory_signals": []}, caplog)
    assert len(_sites(message)) == MAX_SITES


def test_rule_draft_rejection_has_no_sites(caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        output_gate.validate_producers("not json", None, transactions=[TX], produced_by="rule", make_meta=lambda outcome: _meta())
    assert "output_rejected" in caplog.text and "sites=" not in caplog.text


def test_failure_without_a_draft_has_no_rejection_audit(caplog):
    assert _llm_failure(caplog) == []


def _llm_failure(caplog) -> list[str]:
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        output_gate.validate_producers(EMPTY, LlmFailure("timeout"), transactions=[TX], produced_by="rule",
                                       make_meta=lambda outcome: _meta(pipeline_mode="rule_llm", model_id="m", prompt_version="p",
                                                                       llm_outcome=outcome))
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith("llm_draft_rejected")]


def test_contract_names_hold_field_names_and_discriminator_literals_only():
    assert {"transaction_ref", "pointer", "locus", "req_header", "resp_body", "json", "text"} <= CONTRACT_NAMES
    assert not {"info_exposure", "observed", "verification", "query"} & CONTRACT_NAMES  # 판별이 아닌 리터럴 값은 아니다


# ── 집계 ───────────────────────────────────────────────────────────

def _event(sites: str, reasons: str = "draft_schema_invalid") -> dict:
    return {"event": "llm_draft_rejected", "message": f"llm_draft_rejected count=1 reasons={reasons} sites={sites}"}


def test_summary_groups_by_path_and_kind_with_indexes_folded():
    events = [_event("findings.0.evidence.0.transaction_ref:uuid_parsing,findings.1.evidence.0.transaction_ref:uuid_parsing"),
              _event("findings.0.evidence.2.transaction_ref:uuid_parsing"),
              {"event": "llm_draft_rejected", "message": "llm_draft_rejected count=1 reasons=pointer_unresolvable"},
              {"event": "llm_call", "message": "llm_call x=1"}]
    summary = rejection_summary(events)
    assert summary == {"drafts": 3, "reasons": {"draft_schema_invalid": 2, "pointer_unresolvable": 1},
                       "sites": {"findings.*.evidence.*.transaction_ref uuid_parsing": 2}}


def test_runner_reports_rejection_sites_for_its_own_run_only(tmp_path, monkeypatch):
    serving = tmp_path / "serving.json"
    serving.write_text(SERVING.model_dump_json(), encoding="utf-8")
    db = tmp_path / "audit.sqlite3"
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(db))
    monkeypatch.setenv(llm_adapter.API_KEY_ENV, "stubkey0123456789")
    bad = json.dumps({"findings": [{**_finding(), "evidence": [_evidence(transaction_ref="not-a-uuid")]}], "advisory_signals": []})
    with LlmStub(llm_stub.ok(_completion(bad))) as stub:
        monkeypatch.setenv(llm_path.MODE_ENV, "rule_llm")
        monkeypatch.setenv(llm_path.PORT_ENV, str(stub.port))
        monkeypatch.setenv(llm_path.MODEL_ENV, MODEL)
        args = ["--dataset", str(S_V2), "--split", "dev", "--out-dir", str(tmp_path / "out"), "--serving-conditions", str(serving)]
        assert runner.main(args) == 0
        assert runner.main(args) == 0  # 두 번째 실행은 첫 실행의 감사를 세지 않는다
    report = json.loads(next((tmp_path / "out").glob("*.json")).read_text(encoding="utf-8"))
    n = report["selection"]["failure"]["rate"]["n"]
    assert report["rejections"]["drafts"] == n
    assert report["rejections"]["sites"] == {"findings.*.evidence.*.transaction_ref uuid_parsing": n}
    assert sum(1 for e in read_audit_events(db) if e["event"] == "llm_draft_rejected") == 2 * n


def test_rule_only_report_has_no_rejection_block(tmp_path, monkeypatch):
    monkeypatch.delenv(llm_path.MODE_ENV, raising=False)
    assert runner.main(["--dataset", str(S_V2), "--split", "dev", "--out-dir", str(tmp_path)]) == 0
    assert json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))["rejections"] is None


# ── 정적 대조 ──────────────────────────────────────────────────────

def _verdicts(rows) -> dict:
    return {(r["path"], r["pydantic"]): r["verdict"] for r in rows}


def test_current_contract_has_no_missing_constraint():
    rows = gaps()
    assert [r for r in rows if r["verdict"] == "missing"] == []
    assert _verdicts(rows)[("findings[].evidence[].transaction_ref", "uuid")] == "represented"


def test_json_pointer_check_is_reported_as_not_expressible():
    verdicts = _verdicts(gaps())
    assert verdicts[("findings[].evidence[].pointer{locus=resp_body}.body{kind=json}.path", "validator:_check_json_pointer")] == "not_expressible"


def test_range_and_advisories_are_reported_as_excluded():
    verdicts = _verdicts(gaps())
    assert verdicts[("findings[].evidence[].pointer{locus=req_header}.range", "field")] == "excluded"
    assert verdicts[("advisory_signals", "field")] == "excluded"


@pytest.mark.parametrize("drop, key", [("format", ("findings[].evidence[].transaction_ref", "uuid")),
                                       ("minItems", ("findings[].evidence", "min_length")),
                                       ("additionalProperties", ("findings[]", "extra_forbid"))], ids=["format", "minItems", "extra"])
def test_constraint_dropped_from_the_schema_is_reported_missing(drop, key):
    schema = copy.deepcopy(TRANSMISSION_SCHEMA)
    finding = schema["properties"]["findings"]["items"]
    target = {"format": finding["properties"]["evidence"]["items"]["properties"]["transaction_ref"],
              "minItems": finding["properties"]["evidence"], "additionalProperties": finding}[drop]
    del target[drop]
    assert _verdicts(gaps(schema=schema))[key] == "missing"


# ── 변이 확인 ──────────────────────────────────────────────────────

_D = "tests/test_rejection_diagnosis.py::"
GATE = ("sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate")
SRC_MUTATIONS = {
    "allow_list_off": (*GATE, "    return piece if piece in CONTRACT_NAMES else EXTRA_PIECE\n", "    return str(piece)\n",
                       [_D + "test_invented_key_with_a_secret_looking_name_becomes_extra"]),
    "kind_not_checked": (*GATE, '        kind = err["type"] if ERROR_KIND.fullmatch(err["type"]) else EXTRA_PIECE\n',
                         '        kind = err["msg"]\n', [_D + "test_values_and_messages_never_reach_the_audit"]),
    "no_sites": (*GATE, '_error_sites(exc) if event == "llm_draft_rejected" else ()', "()",
                 [_D + "test_rejection_records_the_contract_path_and_the_error_kind"]),
    "no_cap": (*GATE, "    return tuple(sorted(sites))[:MAX_SITES]\n", "    return tuple(sorted(sites))\n", [_D + "test_number_of_sites_is_capped"]),
}
TOOL_MUTATIONS = {
    "indexes_not_folded": ("tools/eval/harness.py", "tools.eval.harness", '"*" if piece.isdigit() else piece', "piece",
                           [_D + "test_summary_groups_by_path_and_kind_with_indexes_folded"]),
    "whole_store_counted": ("tools/eval/runner.py", "tools.eval.runner", "rejection_summary(read_audit_events(audit_db_path())[seen:])",
                            "rejection_summary(read_audit_events(audit_db_path()))", [_D + "test_runner_reports_rejection_sites_for_its_own_run_only"]),
    "schema_always_has_it": ("tools/eval/schema_gap.py", "tools.eval.schema_gap", "    present = node is not None and _schema_has(node, constraint)\n",
                             "    present = True\n", [_D + "test_constraint_dropped_from_the_schema_is_reported_missing[format]"]),
}


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_audit_site_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_diagnosis_tool_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
