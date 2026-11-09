"""선별 준비 — (A) §6.1·§6.2·§6.3. 선정 기준의 재료(실패 합·순이득·needs_review·플래그·소요 시간), 모델별 예산, 환경 실패 재실행.

합성 실행과 스텁 서버로 증명한다. 실서버에 의존하지 않는다.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from sentinel.audit import attach_audit_store, detach_audit_store
from sentinel.pipeline import llm_adapter, llm_path
from sentinel.pipeline.llm_adapter import Limits
from sentinel.pipeline.llm_path import LlmConfig, LlmConfigError, config_from_env
from tests.support import llm_stub
from tests.support.llm_stub import LlmStub
from tests.test_eval_harness import DATASET, L, _anchor, _at, _finding, _result
from tests.test_llm_wiring import MODEL, S_V2, SERVING, _completion, _draft
from tests.test_rule_wiring import _run_mutant
from tools.eval import harness, runner
from tools.eval.harness import FLAGGED_NOTE, PredictionRun
from tools.mutation_guard import copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
FLAG = "hallucinated_literal_suspected"
KEY = "stubkey0123456789"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv(llm_adapter.API_KEY_ENV, KEY)
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "audit.sqlite3"))
    for name in (llm_path.MODE_ENV, llm_path.PORT_ENV, llm_path.MODEL_ENV, *(env for env, _low, _high in llm_path.BUDGET_ENV.values())):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def store(tmp_path):
    """rule_llm은 지문을 못 남기면 LLM 결과를 버린다(audit_write) — 러너 main처럼 저장소를 붙인다."""
    handler = attach_audit_store(tmp_path / "audit-run.sqlite3")
    yield
    detach_audit_store(handler)


def _flagged(finding: dict) -> dict:
    for e in finding["evidence"]:
        e["anomaly_flags"] = [FLAG]
    return {**finding, "status": "needs_review"}


def _synthetic(elapsed: dict | None = None) -> PredictionRun:
    """LLM만 찾은 TP 1 · LLM FP 1(needs_review, 플래그) · hybrid FP 1 · 규칙 TP 1 · 남은 환경 실패 1 · 거부 1."""
    results = {
        "reflected_injection_indicator": _result([_finding(1, "reflected_injection_indicator", _anchor("reflected_injection_indicator"))]),
        "info_exposure": _result([_finding(2, "info_exposure", _anchor("info_exposure"), produced_by="rule")]),
        "clean": _result([_flagged(_finding(3, "security_misconfig", _at("clean", {"locus": "resp_status"})))]),
        "hard": _result([_finding(4, "security_misconfig", _at("hard", {"locus": "resp_status"}), produced_by="hybrid")]),
        "security_misconfig": _result([], "failed:unavailable"),
        "access_control": _result([], "rejected"),
    }
    for name, ms in (elapsed or {}).items():
        results[name]["analysis_meta"]["elapsed_ms"] = ms
    return PredictionRun.model_validate_json(json.dumps(
        {"run_meta": {"split": None, "pipeline_mode": "rule_llm", "model_id": "fixture", "prompt_version": "v0", "ruleset_version": "r0"},
         "results": {str(L[name].transaction_ref): doc for name, doc in results.items()}}))


# ── 선정 기준의 재료 ───────────────────────────────────────────────

def test_net_gain_subtracts_only_llm_false_positives():
    selection = harness.score(DATASET, _synthetic())["selection"]
    assert (selection["llm_only_tp"], selection["llm_fp"], selection["net_gain"]) == (1, 1, 0)


def test_failure_sum_counts_rejections_and_environment_failures_left_after_rerun():
    failure = harness.score(DATASET, _synthetic())["selection"]["failure"]
    assert failure["count"] == 2 and failure["by_outcome"] == {"failed:unavailable": 1, "rejected": 1}
    assert failure["environment_left"] == 1 and failure["rate"]["n"] == 6


def test_needs_review_is_counted_with_its_tp_and_fp():
    report = harness.score(DATASET, _synthetic())
    assert report["selection"]["needs_review"] == {"count": 1, "tp": 0, "fp": 1}
    assert report["J1"]["strict"]["fp"] == 2  # needs_review도 예측이다(§6.1)


def test_flagged_findings_are_counted_with_the_proxy_note():
    assert harness.score(DATASET, _synthetic())["selection"]["flagged_findings"] == {"count": 1, "note": FLAGGED_NOTE}


def test_elapsed_median_and_max_are_reported():
    elapsed = harness.score(DATASET, _synthetic({"clean": 30, "hard": 10, "info_exposure": 20}))["selection"]["elapsed_ms"]
    assert elapsed == {"median": 5.0, "max": 30}  # 6건: 0·0·0·10·20·30


def test_rule_only_report_has_no_selection_block():
    assert runner.run(DATASET, {})["selection"] is None


# ── 모델별 예산 ────────────────────────────────────────────────────

def _rule_llm(monkeypatch, port: str = "18080") -> None:
    monkeypatch.setenv(llm_path.MODE_ENV, "rule_llm")
    monkeypatch.setenv(llm_path.PORT_ENV, port)
    monkeypatch.setenv(llm_path.MODEL_ENV, MODEL)


def test_budget_settings_reach_the_limits(monkeypatch):
    _rule_llm(monkeypatch)
    monkeypatch.setenv("SENTINEL_LLM_VIEW_BYTES", "4096")
    monkeypatch.setenv("SENTINEL_LLM_MAX_TOKENS", "512")
    monkeypatch.setenv("SENTINEL_LLM_DEADLINE_SECONDS", "240")
    limits = config_from_env().limits
    assert (limits.view_bytes, limits.max_tokens, limits.deadline_seconds, limits.io_timeout_seconds) == (4096, 512, 240, 240)


def test_no_budget_settings_keep_the_defaults(monkeypatch):
    _rule_llm(monkeypatch)
    assert config_from_env().limits == llm_adapter.DEFAULT_LIMITS


@pytest.mark.parametrize("env, value", [("SENTINEL_LLM_MAX_TOKENS", "2048"), ("SENTINEL_LLM_DEADLINE_SECONDS", "240"),
                                        ("SENTINEL_LLM_VIEW_BYTES", "4096")], ids=["max_tokens", "deadline", "view"])
def test_changing_a_budget_setting_changes_the_prompt_version(monkeypatch, env, value):
    _rule_llm(monkeypatch)
    before = config_from_env().prompt_version
    monkeypatch.setenv(env, value)
    assert config_from_env().prompt_version != before


@pytest.mark.parametrize("value", ["0", "-5", "1.5", "abc", "99999999", "８"], ids=["zero", "negative", "float", "text", "huge", "fullwidth"])
def test_invalid_budget_is_refused(monkeypatch, value):
    _rule_llm(monkeypatch)
    monkeypatch.setenv("SENTINEL_LLM_MAX_TOKENS", value)
    with pytest.raises(LlmConfigError, match="llm_budget_invalid"):
        config_from_env()


def test_budget_reaches_the_request(monkeypatch):
    with LlmStub(llm_stub.ok(_completion(_draft()))) as stub:
        _rule_llm(monkeypatch, str(stub.port))
        monkeypatch.setenv("SENTINEL_LLM_MAX_TOKENS", "77")
        runner.run(S_V2, {}, "dev", config_from_env(), SERVING)
    assert all(json.loads(r.partition(b"\r\n\r\n")[2])["max_tokens"] == 77 for r in stub.requests)


# ── 환경 실패 재실행 ───────────────────────────────────────────────

def _fails_first(times: int):
    """처음 times번은 500, 그 뒤로는 빈 초안."""
    calls = [0]

    def respond(conn: socket.socket) -> None:
        calls[0] += 1
        if calls[0] <= times:
            llm_stub.status(b"500 Internal Server Error")(conn)
        else:
            llm_stub.ok(_completion(_draft()))(conn)
    return respond


def _config(port: int) -> LlmConfig:
    return LlmConfig(MODEL, port, Limits(io_timeout_seconds=5.0, deadline_seconds=5.0))


def test_environment_failure_is_rerun_once_and_recorded(store):
    with LlmStub(_fails_first(1)) as stub:
        report = runner.run(S_V2, {}, "dev", _config(stub.port), SERVING, rerun_environment=True)
    [rerun] = report["reruns"]
    assert rerun == {"transaction_ref": rerun["transaction_ref"], "first": "failed:unavailable", "second": "ok"}
    assert report["selection"]["failure"]["count"] == 0
    assert len(stub.requests) == report["selection"]["failure"]["rate"]["n"] + 1


def test_environment_failure_left_after_rerun_counts_toward_the_failure_sum(store):
    with LlmStub(llm_stub.status(b"500 Internal Server Error")) as stub:
        report = runner.run(S_V2, {}, "dev", _config(stub.port), SERVING, rerun_environment=True)
    n = report["selection"]["failure"]["rate"]["n"]
    assert len(report["reruns"]) == n and all(r["second"] == "failed:unavailable" for r in report["reruns"])
    assert report["selection"]["failure"]["count"] == n and report["selection"]["failure"]["environment_left"] == n
    assert len(stub.requests) == 2 * n


def test_without_the_option_nothing_is_rerun(store):
    with LlmStub(_fails_first(1)) as stub:
        report = runner.run(S_V2, {}, "dev", _config(stub.port), SERVING)
    assert report["reruns"] is None and report["selection"]["failure"]["environment_left"] == 1


def test_rerun_needs_rule_llm():
    with pytest.raises(runner.RunRejected, match="rerun_without_llm"):
        runner.run(S_V2, {}, "dev", rerun_environment=True)


def test_quality_failures_are_not_rerun(store):
    with LlmStub(llm_stub.ok(_completion("not json"))) as stub:
        report = runner.run(S_V2, {}, "dev", _config(stub.port), SERVING, rerun_environment=True)
    assert report["reruns"] == [] and report["selection"]["failure"]["by_outcome"] == {"failed:unparseable": report["selection"]["failure"]["count"]}


# ── 변이 확인 ──────────────────────────────────────────────────────

_S = "tests/test_selection_prep.py::"
HARN = ("tools/eval/harness.py", "tools.eval.harness")
RUN = ("tools/eval/runner.py", "tools.eval.runner")
TOOL_MUTATIONS = {
    "hybrid_counted_as_llm_fp": (*HARN, '    llm_fp = sum(1 for p in fps if p.produced_by == "llm")\n', '    llm_fp = sum(1 for p in fps if p.produced_by != "rule")\n',
                                 [_S + "test_net_gain_subtracts_only_llm_false_positives"]),
    "net_gain_ignores_fp": (*HARN, '"net_gain": len(llm_only) - llm_fp,', '"net_gain": len(llm_only),', [_S + "test_net_gain_subtracts_only_llm_false_positives"]),
    "environment_failures_left_out": (*HARN, 'failed = Counter(outcome for outcome in judged.values() if outcome != "ok")',
                                      'failed = Counter(outcome for outcome in judged.values() if outcome != "ok" and outcome not in ENV_FAILURES)',
                                      [_S + "test_failure_sum_counts_rejections_and_environment_failures_left_after_rerun",
                                       _S + "test_environment_failure_left_after_rerun_counts_toward_the_failure_sum"]),
    "needs_review_not_counted": (*HARN, '    needs_review = [p for p in preds if p.status == "needs_review"]\n', "    needs_review = []\n",
                                 [_S + "test_needs_review_is_counted_with_its_tp_and_fp"]),
    "flag_not_read": (*HARN, "any(e.anomaly_flags for e in f.evidence))", "False)", [_S + "test_flagged_findings_are_counted_with_the_proxy_note"]),
    "rerun_skipped": (*RUN, "        if first in ENV_FAILURES:\n", "        if False:\n", [_S + "test_environment_failure_is_rerun_once_and_recorded"]),
    "rerun_everything": (*RUN, "        if first in ENV_FAILURES:\n", '        if first != "ok":\n', [_S + "test_quality_failures_are_not_rerun"]),
}
SRC_MUTATIONS = {
    "budget_ignored": ("sentinel/pipeline/llm_path.py", "sentinel.pipeline.llm_path", "limits=_budget())", ")",
                       [_S + "test_budget_settings_reach_the_limits", _S + "test_changing_a_budget_setting_changes_the_prompt_version[max_tokens]"]),
    "budget_not_checked": ("sentinel/pipeline/llm_path.py", "sentinel.pipeline.llm_path",
                           "        if not (text.isascii() and text.isdigit() and low <= int(text) <= high):\n", "        if not text.isdigit():\n",
                           [_S + "test_invalid_budget_is_refused[huge]", _S + "test_invalid_budget_is_refused[zero]"]),
    "deadline_without_io_timeout": ("sentinel/pipeline/llm_path.py", "sentinel.pipeline.llm_path",
                                    '        values["io_timeout_seconds"] = values["deadline_seconds"]\n', "        pass\n",
                                    [_S + "test_budget_settings_reach_the_limits"]),
}


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_selection_tool_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_budget_path_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)
