"""층 B 러너 — 동결 데이터셋을 실제 ②③④로 통과시켜 채점한다. `eval_harness`((A) §3.5).

'위조 거부'로 증명한다: ②③을 건너뛰는 경로, 메타와 다른 머리, 전부 거부 실행, 데이터셋 기록과 다른 split.
S v1 수치는 측정이 아니라 동작 확인이다((A) §6.2 — S v1은 규칙에 대해 오염된 스모크 집합).
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.pipeline import entry, rule_engine, sanitization_check, schema_gate
from tools.eval import runner
from tools.eval.harness import PredictionRun, RunMeta, wilson
from tools.eval.runner import RunRejected
from tools.mutation_guard import apply_mutation, copy_with_mutation
from tests.test_rule_wiring import _RawDraft, _finding, _run_mutant
from tests.test_sanitization import FAKES, _plant
from tests.test_schema import _env, _raw

REPO_ROOT = Path(__file__).resolve().parents[1]
S_V1 = REPO_ROOT / "datasets" / "S" / "v1"
RAWS = [p.read_bytes() for p in sorted((S_V1 / "envelopes").glob("*.json"))]
REFLECTED = "0d851bfd-db38-46eb-ad00-1501b42137ed"
IDOR = "fab71ff6-1f53-4306-959e-6039927ea4c2"


def _report(split=None) -> dict:
    return runner.run(S_V1, {}, split)


def _estimates(node) -> list[dict]:
    """보고서 안의 비율 항목 전부(value·n·interval·note)."""
    if isinstance(node, dict):
        found = [node] if {"value", "n", "interval", "note"} <= set(node) else []
        return found + [e for v in node.values() for e in _estimates(v)]
    if isinstance(node, list):
        return [e for v in node for e in _estimates(v)]
    return []


# ── S v1 동작 확인(측정 아님) ──────────────────────────────────────

def test_s_v1_report_has_the_expected_counts():
    report = _report()
    strict = report["J1"]["strict"]
    assert (strict["tp"], strict["fp"], strict["fn"]) == (3, 0, 1)
    assert report["J1"]["per_category"]["access_control"]["recall"]["n"] == 1  # 유일한 FN = IDOR
    assert report["J1"]["per_category"]["access_control"]["fn"] == 1
    assert report["J2"]["output_rejected"] == [] and report["undetermined"] == 0
    assert IDOR not in report["matches"]


def test_s_v1_hard_negative_is_not_flagged():
    report = _report()
    assert report["J3"]["hard_negative"]["interval"] == wilson(0, 1)["interval"]
    assert report["J3"]["verified_clean"]["interval"] == wilson(0, 2)["interval"]


def test_every_s_v1_point_estimate_is_withheld():
    estimates = _estimates(_report())
    assert estimates and all(e["value"] is None for e in estimates)
    assert all(re.fullmatch(r"표본 (부족\(n=[1-9][0-9]*\)|없음\(n=0\))", e["note"]) for e in estimates)


# ── 실제 경로 ──────────────────────────────────────────────────────

def test_every_envelope_goes_through_the_entry_function_and_each_stage(monkeypatch):
    calls: list[str] = []
    for module, name in ((entry, "analyze"), (schema_gate, "parse_envelope"), (sanitization_check, "verify_sanitization")):
        real = getattr(module, name)
        monkeypatch.setattr(module, name, lambda *a, _n=name, _r=real, **k: calls.append(_n) or _r(*a, **k))
    runner.predictions(RAWS, {})
    assert calls == ["analyze", "parse_envelope", "verify_sanitization"] * len(RAWS)


def test_input_that_stage_three_rejects_is_refused_not_scored():
    raw = _raw(_plant("response_body", FAKES["jwt"]))
    with pytest.raises(RunRejected, match="input_rejected"):
        runner.predictions([raw], {})


def test_input_that_stage_two_rejects_is_refused_not_scored():
    with pytest.raises(RunRejected, match="input_rejected"):
        runner.predictions([b"{}"], {})


def test_runner_reaches_the_pipeline_only_through_the_entry_function():
    tree = ast.parse(Path(runner.__file__).read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "sentinel.pipeline"
                for a in n.names}
    assert imported == {"entry", "llm_path", "sanitization_check", "schema_gate"}  # 뒤의 셋은 설정 읽기와 거부 예외 이름만
    calls = {(n.func.value.id, n.func.attr) for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id in imported}
    assert calls == {("entry", "analyze"), ("llm_path", "config_from_env")}


# ── J9 머리: 결과의 메타에서만 ─────────────────────────────────────

def test_header_is_read_from_the_analysis_meta():
    header = _report()["header"]
    assert (header["pipeline_mode"], header["model_id"], header["prompt_version"]) == ("rule_only", None, None)
    assert header["ruleset_version"] == rule_engine.RULESET_VERSION


def test_header_follows_the_meta_not_a_runner_constant(monkeypatch):
    monkeypatch.setattr(rule_engine, "RULESET_VERSION", "rules-other")
    assert _report()["header"]["ruleset_version"] == "rules-other"


def _forged_run(**over) -> PredictionRun:
    results = runner.predictions(RAWS, {})
    meta = {"split": None, "pipeline_mode": "rule_only", "model_id": None, "prompt_version": None,
            "ruleset_version": rule_engine.RULESET_VERSION, **over}
    return PredictionRun(run_meta=RunMeta(**meta), results=results)


def test_header_equal_to_the_meta_is_accepted():
    assert _forged_run().run_meta.pipeline_mode == "rule_only"


@pytest.mark.parametrize("over", [{"ruleset_version": "rules-forged"},
                                  {"pipeline_mode": "rule_llm", "model_id": "m", "prompt_version": "v"}],
                         ids=["ruleset_version", "pipeline_mode_and_model"])
def test_header_that_differs_from_the_meta_is_refused(over):
    with pytest.raises(ValidationError):
        _forged_run(**over)


def test_results_whose_metas_disagree_are_refused(monkeypatch):
    versions = iter(f"rules-{i}" for i in range(len(RAWS)))
    real = entry.analyze

    def analyze(raw, snapshot, llm_config=None):
        monkeypatch.setattr(rule_engine, "RULESET_VERSION", next(versions))
        return real(raw, snapshot)

    monkeypatch.setattr(entry, "analyze", analyze)
    with pytest.raises(RunRejected, match="analysis_meta_disagrees"):
        _report()


# ── 거부된 실행 ────────────────────────────────────────────────────

def _reject_when(monkeypatch, should_reject) -> None:
    real = rule_engine.evaluate
    monkeypatch.setattr(rule_engine, "evaluate",
                        lambda tx: [_RawDraft(_finding())] if should_reject(tx) else real(tx))


def test_partly_rejected_run_turns_the_labels_into_fn_and_reads_the_remaining_meta(monkeypatch):
    _reject_when(monkeypatch, lambda tx: str(tx.meta.transaction_id) == REFLECTED)
    report = _report()
    assert report["J2"]["output_rejected"] == [REFLECTED] and report["J2"]["fn_from_rejected"] == 1
    strict = report["J1"]["strict"]
    assert (strict["tp"], strict["fn"]) == (2, 2) and report["header"]["pipeline_mode"] == "rule_only"


def test_fully_rejected_run_gives_no_report(monkeypatch):
    _reject_when(monkeypatch, lambda tx: True)
    with pytest.raises(RunRejected, match="all_output_rejected"):
        _report()


def test_fully_rejected_run_writes_no_file_and_exits_non_zero(monkeypatch, tmp_path, capsys):
    _reject_when(monkeypatch, lambda tx: True)
    assert runner.main(["--out-dir", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists() and "all_output_rejected" in capsys.readouterr().err


def test_response_that_was_never_analyzed_is_refused(monkeypatch):
    class NotAnalyzed:
        analysis_status = "not_implemented"
        result = None

    monkeypatch.setattr(entry, "analyze", lambda raw, snapshot, llm_config=None: NotAnalyzed())
    with pytest.raises(RunRejected, match="unexpected_response"):
        runner.predictions(RAWS, {})


# ── split: 데이터셋 기록 ───────────────────────────────────────────

def test_s_v1_has_no_split_so_the_header_says_null_and_no_split():
    header = _report()["header"]
    assert header["split"] is None and header["split_note"] == "분할 없음"


@pytest.mark.parametrize("split", ["dev", "test"])
def test_split_argument_is_refused_when_the_dataset_records_none(split):
    with pytest.raises(RunRejected, match="split_differs_from_dataset"):
        _report(split)


def test_split_has_no_default_in_the_run_meta():
    with pytest.raises(ValidationError):
        RunMeta(pipeline_mode="rule_only", model_id=None, prompt_version=None, ruleset_version="r")


# ── 결정론·산출물 ──────────────────────────────────────────────────

def test_same_input_gives_the_same_report():
    assert _report() == _report()


def test_report_carries_no_finding_id():
    report = _report()
    assert sorted(report["matches"]) == report["matches"] and REFLECTED in report["matches"]
    assert "finding_id" not in json.dumps(report)


def test_main_writes_the_report_and_two_runs_are_byte_identical(tmp_path, capsys):
    first, second = tmp_path / "a", tmp_path / "b"
    assert runner.main(["--out-dir", str(first)]) == 0 and runner.main(["--out-dir", str(second)]) == 0
    assert (first / "S-v1.json").read_bytes() == (second / "S-v1.json").read_bytes()
    assert '"ruleset_version"' in capsys.readouterr().out


def test_default_output_path_is_ignored_by_git():
    path = runner.DEFAULT_OUT_DIR.relative_to(REPO_ROOT) / "S-v1.json"
    assert subprocess.run(["git", "check-ignore", "-q", path.as_posix()], cwd=REPO_ROOT).returncode == 0


# ── make eval: 실제 타깃 ───────────────────────────────────────────
# pytest의 `pythonpath` 설정은 이 프로세스 안에서만 듣는다 — 타깃의 실패를 가렸던 경로라 하위 프로세스로 돌린다.

def _make_eval(makefile: Path, out_dir: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTEST_ADDOPTS", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    return subprocess.run(["make", "-f", makefile.as_posix(), "eval", f"EVAL_ARGS=--out-dir={out_dir.as_posix()}"],
                          cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)


def test_make_eval_runs_the_real_target_without_the_pytest_path(tmp_path):
    r = _make_eval(REPO_ROOT / "Makefile", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    header = json.loads((tmp_path / "S-v1.json").read_text(encoding="utf-8"))["header"]
    assert (header["dataset_id"], header["split"], header["split_note"]) == ("S-v1", None, "분할 없음")
    assert (header["pipeline_mode"], header["model_id"], header["prompt_version"]) == ("rule_only", None, None)
    assert header["ruleset_version"] == rule_engine.RULESET_VERSION


def test_make_eval_fails_when_the_target_loses_its_python_path(tmp_path):
    """변이: 타깃의 PYTHONPATH를 지운 사본은 실패한다. 이 줄이 하중을 진다는 증명 — 사본이 실제로 쓰였는지는 오류 내용이 말한다."""
    source = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    mutant = tmp_path / "Makefile"
    mutant.write_text(apply_mutation(source, "eval: export PYTHONPATH := src\n", ""), encoding="utf-8")
    r = _make_eval(mutant, tmp_path / "out")
    assert r.returncode != 0 and "No module named 'sentinel'" in r.stdout + r.stderr
    assert not (tmp_path / "out").exists()


# ── 변이 확인 ──────────────────────────────────────────────────────

_R = "tests/test_eval_runner.py::"
ANALYZE_CALL = "            response = entry.analyze(raw, manifest_snapshot, llm_config)\n"
TOOL_MUTATIONS = {
    "stage_three_skipped": ("tools/eval/runner.py", "tools.eval.runner", ANALYZE_CALL,
                            "            from sentinel.pipeline import execution\n"
                            "            from sentinel.pipeline.sanitization_check import SanitizedEnvelope\n"
                            "            response = execution.build_execution_response(SanitizedEnvelope("
                            "schema_gate.parse_envelope(raw).model_dump_json(include={'transactions'})), manifest_snapshot)\n",
                            [_R + "test_input_that_stage_three_rejects_is_refused_not_scored",
                             _R + "test_every_envelope_goes_through_the_entry_function_and_each_stage",
                             _R + "test_runner_reaches_the_pipeline_only_through_the_entry_function"]),
    "rule_engine_called_directly": ("tools/eval/runner.py", "tools.eval.runner", ANALYZE_CALL,
                                    "            from sentinel.pipeline import rule_engine\n"
                                    "            rule_engine.evaluate(schema_gate.parse_envelope(raw).transactions[0])\n"
                                    "            response = entry.analyze(raw, manifest_snapshot, llm_config)\n",
                                    [_R + "test_runner_reaches_the_pipeline_only_through_the_entry_function"]),
    "header_from_a_runner_constant": ("tools/eval/runner.py", "tools.eval.runner",
                                      "ruleset_version=metas[0].ruleset_version,", 'ruleset_version="rules-1",',
                                      [_R + "test_header_follows_the_meta_not_a_runner_constant"]),
    "header_check_off": ("tools/eval/harness.py", "tools.eval.harness",
                         "            if not _same_producer(self.run_meta, r.analysis_meta):\n",
                         "            if False:\n",
                         [_R + "test_header_that_differs_from_the_meta_is_refused[ruleset_version]",
                          _R + "test_results_whose_metas_disagree_are_refused"]),
    "all_rejected_check_off": ("tools/eval/runner.py", "tools.eval.runner",
                               '    if not metas:\n        raise RunRejected("all_output_rejected")\n'
                               "    return RunMeta(split=split, pipeline_mode=metas[0].pipeline_mode, model_id=metas[0].model_id,\n"
                               "                   prompt_version=metas[0].prompt_version, ruleset_version=metas[0].ruleset_version,\n",
                               '    if not metas:\n        return RunMeta(split=split, pipeline_mode="rule_only", model_id=None, '
                               'prompt_version=None, ruleset_version="x")\n'
                               "    return RunMeta(split=split, pipeline_mode=metas[0].pipeline_mode, model_id=metas[0].model_id,\n"
                               "                   prompt_version=metas[0].prompt_version, ruleset_version=metas[0].ruleset_version,\n",
                               [_R + "test_fully_rejected_run_gives_no_report",
                                _R + "test_fully_rejected_run_writes_no_file_and_exits_non_zero"]),
    "split_argument_not_checked": ("tools/eval/runner.py", "tools.eval.runner",
                                   "        if split is not None:\n", "        if False:\n",
                                   [_R + "test_split_argument_is_refused_when_the_dataset_records_none[dev]"]),
    "finding_id_left_in_the_report": ("tools/eval/runner.py", "tools.eval.runner",
                                      '    return {**report, "reruns": reruns, "matches": sorted(ref for _finding_id, ref in report["matches"])}\n',
                                      "    return report\n",
                                      [_R + "test_same_input_gives_the_same_report",
                                       _R + "test_main_writes_the_report_and_two_runs_are_byte_identical"]),
}


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_each_runner_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
