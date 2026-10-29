"""평가 하네스 — 층 A 채점기 자기 증명. `eval_harness` · `label_isolation`. (A) §6.1 매칭(사전순 최소 최대 매칭, CNA 전순서),
§6.2 라벨 상태, §6.3 지표.

범위(정직 표기): 채점할 모델 출력이 없으므로, 정답을 아는 예측 픽스처를 손으로 만들어 채점기가 정확한 수를 내는지 본다 —
'채점 로직이 정답을 아는 입력에서 정확하고, 최대 매칭을 보장하며, 결정론적'까지가 증명 범위다. 실제 모델 채점(층 B)은 아니다.
데이터는 동결 S v1의 Envelope를 그대로 쓰고, 라벨이 달라야 하는 구성(unlabeled·최대 매칭)은 임시 사본의 라벨만 바꾼다
(동결본은 건드리지 않는다). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.canonical_address import CNA, cna_sort_key
from tools.arch_boundary import LABELS, scan_package, scan_source
from tools.dataset.labelfile import LabelFile
from tools.eval import harness
from tools.eval.harness import DatasetRejected, PredictionRun, score, wilson
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "datasets" / "S" / "v1"
ENGINE_ROOT = REPO_ROOT / "src" / "sentinel"


def _labels(dataset: Path = DATASET) -> dict:
    """category → 라벨(labeled_positive), 'clean'·'hard' → verified_clean 라벨."""
    lf = LabelFile.model_validate_json((dataset / "labels.json").read_bytes())
    out = {}
    for label in lf.labels:
        if label.label_status == "labeled_positive":
            out[label.categories[0]] = label
        elif label.hard_negative:
            out["hard"] = label
        else:
            out["clean"] = label
    return out


L = _labels()


def _fid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _anchor(name: str, i: int = 0) -> tuple[str, dict]:
    label = L[name]
    return str(label.transaction_ref), label.anchors[i].model_dump(mode="json", exclude_none=True)


def _at(name: str, pointer: dict) -> tuple[str, dict]:
    return str(L[name].transaction_ref), pointer


def _finding(n: int, category: str, *evidence: tuple[str, dict], produced_by: str = "llm") -> dict:
    return {"finding_id": _fid(n), "category": category, "hypothesis": "h", "claim_basis": "observed",
            "severity_if_true": None, "status": "unverified", "produced_by": produced_by, "limitations": [],
            "next_steps": [],
            "evidence": [{"transaction_ref": ref, "pointer": ptr, "observation": "o", "corroboration": "not_run",
                          "anomaly_flags": [], "review_required": True} for ref, ptr in evidence]}


def _result(findings: list[dict]) -> dict:
    return {"schema_version": "1.0", "analyzed_refs": sorted({e["transaction_ref"] for f in findings for e in f["evidence"]}),
            "findings": findings, "advisory_signals": [],
            "analysis_meta": {"model_id": "fixture", "policy_version": "p", "prompt_version": "v0", "ruleset_version": "r0",
                              "elapsed_ms": 0, "pipeline_mode": "fixture", "manifest_snapshot": {}}}


def _run(findings: list[dict], rejected: tuple[str, ...] = (), extra: dict | None = None) -> PredictionRun:
    results: dict = {str(L[c].transaction_ref): "output_rejected" for c in rejected}
    if findings:
        results[findings[0]["evidence"][0]["transaction_ref"]] = _result(findings)
    results.update(extra or {})
    return PredictionRun.model_validate_json(json.dumps(
        {"run_meta": {"split": "dev", "model_id": "fixture", "prompt_version": "v0", "ruleset_version": "r0"},
         "results": results}))


def _correct(n0: int = 1) -> list[dict]:
    return [_finding(n0 + i, c, _anchor(c)) for i, c in enumerate(
        ["reflected_injection_indicator", "info_exposure", "security_misconfig", "access_control"])]


def _strict(report) -> tuple[int, int, int]:
    s = report["J1"]["strict"]
    return s["tp"], s["fp"], s["fn"]


def _copy_with_labels(tmp_path: Path, edit) -> Path:
    target = tmp_path / "S" / "v1"
    shutil.copytree(DATASET, target)
    doc = json.loads((target / "labels.json").read_bytes())
    edit(doc)
    (target / "labels.json").write_bytes(json.dumps(doc, ensure_ascii=False, indent=2).encode())
    return target


# ── 층 A: 정답을 아는 입력에서 정확한 수 ───────────────────────────────────

def test_all_correct_predictions_score_perfectly():
    report = score(DATASET, _run(_correct()))
    assert _strict(report) == (4, 0, 0) and report["undetermined"] == 0
    assert report["header"]["dataset_id"] == "S-v1" and report["header"]["split"] == "dev"


def test_planted_tp_fp_fn_counts_are_exact():
    findings = [_finding(1, "reflected_injection_indicator", _anchor("reflected_injection_indicator")),
                _finding(2, "info_exposure", _anchor("info_exposure")),
                _finding(3, "info_exposure", _at("info_exposure", {"locus": "resp_status"}))]  # 위치 틀림 → FP
    report = score(DATASET, _run(findings))
    assert _strict(report) == (2, 1, 2)
    assert report["J1"]["per_category"]["security_misconfig"] == {**report["J1"]["per_category"]["security_misconfig"],
                                                                  "tp": 0, "fp": 0, "fn": 1}


def test_finding_on_hard_negative_is_fp_and_counted_in_j3():
    findings = [*_correct(), _finding(9, "reflected_injection_indicator", _at("hard", {"locus": "req_param",
                                                                                     "location": "query", "name": "q"}))]
    report = score(DATASET, _run(findings))
    assert _strict(report) == (4, 1, 0)
    assert report["J3"]["hard_negative"]["n"] == 1 and report["J3"]["hard_negative"]["interval"][1] == 1
    assert report["J3"]["verified_clean"]["n"] == 2  # 일반 clean + hard negative


def test_output_rejected_transaction_turns_all_its_labels_into_fn():
    findings = [f for f in _correct() if f["category"] != "access_control"]
    report = score(DATASET, _run(findings, rejected=("access_control",)))
    assert _strict(report) == (3, 0, 1)
    assert report["J2"]["fn_from_rejected"] == 1 and report["J2"]["output_rejected"] == [str(L["access_control"].transaction_ref)]


def test_exact_duplicates_are_merged_before_scoring():
    dup = _finding(7, "info_exposure", _anchor("info_exposure"))
    report = score(DATASET, _run([*_correct(), dup]))
    assert _strict(report) == (4, 0, 0) and report["duplicates"]["merged_exact"] == 1


def test_left_over_duplicate_after_one_to_one_matching_is_fp():
    """같은 라벨을 다른 위치로 가리킨 두 예측: 병합되지 않고(CNA 집합이 다름), 1:1이라 하나는 FP + 중복률."""
    second = _finding(8, "reflected_injection_indicator", _anchor("reflected_injection_indicator", 1))
    report = score(DATASET, _run([*_correct(), second]))
    assert _strict(report) == (4, 1, 0) and report["duplicates"]["left_over_fp"] == 1


def test_right_location_wrong_category_counts_only_in_location_metrics_and_confusion():
    wrong = _finding(1, "info_exposure", _anchor("reflected_injection_indicator"))
    report = score(DATASET, _run([wrong]))
    assert _strict(report) == (0, 1, 4)
    assert report["J1"]["location_only"]["tp"] == 1
    assert report["J1"]["confusion"] == [["reflected_injection_indicator", "info_exposure", 1]]


def test_right_category_wrong_location_is_tp_nowhere():
    wrong = _finding(1, "reflected_injection_indicator", _at("reflected_injection_indicator", {"locus": "resp_status"}))
    report = score(DATASET, _run([wrong]))
    assert _strict(report) == (0, 1, 4) and report["J1"]["location_only"]["tp"] == 0


def test_prediction_on_unlabeled_transaction_is_undetermined_not_fp(tmp_path):
    clean_ref = str(L["clean"].transaction_ref)

    def unlabel(doc):
        for x in doc["labels"]:
            if x["transaction_ref"] == clean_ref:
                x["label_status"] = "unlabeled"
    dataset = _copy_with_labels(tmp_path, unlabel)
    report = score(dataset, _run([*_correct(), _finding(9, "info_exposure", (clean_ref, {"locus": "resp_status"}))]))
    assert _strict(report) == (4, 0, 0) and report["undetermined"] == 1


def _max_matching_dataset(tmp_path: Path) -> tuple[Path, str, str]:
    """두 positive 라벨 A < B(정렬 순)를 같은 category로 바꾼 사본."""
    positives = sorted((L[c] for c in ("reflected_injection_indicator", "info_exposure", "security_misconfig",
                                       "access_control")), key=lambda x: str(x.transaction_ref))
    a, b = positives[0], positives[-1]

    def same_category(doc):
        for x in doc["labels"]:
            if x["transaction_ref"] in (str(a.transaction_ref), str(b.transaction_ref)):
                x["categories"] = ["access_control"]
    return _copy_with_labels(tmp_path, same_category), str(a.transaction_ref), str(b.transaction_ref)


def _first_anchor(ref: str) -> tuple[str, dict]:
    label = next(x for x in L.values() if str(x.transaction_ref) == ref)
    return ref, label.anchors[0].model_dump(mode="json", exclude_none=True)


def test_maximum_matching_takes_both_where_greedy_would_take_one(tmp_path):
    """p1은 A·B 둘 다, p2는 A만 매칭 가능. 정렬상 p1이 먼저고(최소 CNA 같음 → finding_id) A가 먼저다 —
    탐욕이면 p1→A로 p2가 FP(1 TP), 최대 매칭은 p1→B·p2→A로 2 TP."""
    dataset, a_ref, b_ref = _max_matching_dataset(tmp_path)
    p1 = _finding(1, "access_control", _first_anchor(a_ref), _first_anchor(b_ref))
    p2 = _finding(2, "access_control", _first_anchor(a_ref))
    report = score(dataset, _run([p1, p2]))
    assert _strict(report)[:2] == (2, 0)
    assert report["matches"] == sorted([[_fid(1), b_ref], [_fid(2), a_ref]])


def _tie_findings() -> list[dict]:
    """같은 라벨에만 매칭 가능한 두 예측 — 최소 CNA가 같아 finding_id가 동점을 깬다."""
    ref, anchor = _anchor("info_exposure")
    return [_finding(5, "info_exposure", (ref, anchor), (ref, {"locus": "resp_status"})),
            _finding(6, "info_exposure", (ref, anchor), (ref, {"locus": "req_line", "part": "method"}))]


def test_tie_is_broken_by_the_sort_keys_and_is_deterministic_under_input_reordering():
    reports = []
    rng = random.Random(7)
    for _ in range(8):
        findings = _tie_findings()
        rng.shuffle(findings)
        reports.append(score(DATASET, _run(findings)))
    assert all(r == reports[0] for r in reports)  # 입력 순서와 무관하게 같은 보고
    assert reports[0]["matches"] == [[_fid(5), str(L["info_exposure"].transaction_ref)]]  # 정렬상 앞선 예측이 TP
    assert _strict(reports[0])[:2] == (1, 1)


def test_cna_total_order_is_explicit_and_fixed():
    a, b = uuid.UUID(int=1), uuid.UUID(int=2)
    cnas = [CNA(b, ("resp_status",)), CNA(a, ("param", "form", "pw", 10)), CNA(a, ("param", "form", "pw", 2)),
            CNA(a, ("body_json", "req", "/b")), CNA(a, ("body_json", "req", "/a")), CNA(a, ("req_line.path",))]
    assert [(c.transaction_ref.int, c.node) for c in sorted(cnas, key=cna_sort_key)] == [
        (1, ("body_json", "req", "/a")), (1, ("body_json", "req", "/b")), (1, ("param", "form", "pw", 2)),
        (1, ("param", "form", "pw", 10)), (1, ("req_line.path",)), (2, ("resp_status",))]
    with pytest.raises(TypeError):
        cna_sort_key(CNA(a, ("header", "req", "x", True)))


# ── 지표 표기 ─────────────────────────────────────────────────────

@pytest.mark.parametrize("successes,n,has_value", [(0, 0, False), (4, 4, False), (1, 6, False), (150, 160, True),
                                                   (90, 200, True)])
def test_j8_small_samples_get_no_point_estimate(successes, n, has_value):
    w = wilson(successes, n)
    assert (w["value"] is not None) is has_value
    if not has_value and n:
        assert w["note"] == f"표본 부족(n={n})" and w["interval"][0] <= successes / n <= w["interval"][1]


def test_unimplemented_metrics_are_reported_honestly():
    report = score(DATASET, _run(_correct()))
    assert report["J4"] == "not_run" and report["J5"].startswith("보류")
    assert report["J7"]["version_comparison"] == "비교할 실행 없음(단일 실행)"
    assert report["J1"]["strict"]["precision"]["note"] == "표본 부족(n=4)"  # 첫 동결은 작다 — 숫자를 내지 않음


def test_j6_counts_by_producer_and_llm_only_tp():
    findings = _correct()
    findings[0]["produced_by"] = "rule"
    findings.append(_finding(9, "reflected_injection_indicator", _anchor("reflected_injection_indicator", 1),
                             produced_by="llm"))
    report = score(DATASET, _run(findings))
    by = report["J6"]["by_produced_by"]
    # reflected 라벨에 rule(파라미터 q)·llm(응답 /query) 둘 다 매칭 가능 — 정렬 키상 body_json < param이라 llm이 TP,
    # rule은 남은 중복 FP. llm만 찾은 TP는 rule 예측이 매칭될 수 없었던 나머지 3개.
    assert (by["rule"]["tp"], by["rule"]["fp"], by["llm"]["tp"]) == (0, 1, 4) and report["J6"]["llm_only_tp"] == 3


def test_advisory_signals_are_not_scored():
    result = _result(_correct())
    ref, anchor = _anchor("security_misconfig")
    result["advisory_signals"] = [{"type": "out_of_scope_advisory", "topic": "csrf", "suggestion": "s",
                                   "basis": [{"transaction_ref": ref, "pointer": anchor, "observation": "o",
                                              "corroboration": "not_run", "anomaly_flags": [], "review_required": True}]}]
    run = _run([], extra={ref: result})
    assert _strict(score(DATASET, run)) == (4, 0, 0)


def test_report_is_identical_across_repeated_runs():
    run = _run([*_correct(), *_tie_findings()])
    assert score(DATASET, run) == score(DATASET, run) == score(DATASET, run)


# ── 데이터 관문 ───────────────────────────────────────────────────

def test_harness_refuses_a_dataset_failing_freeze_checks(tmp_path):
    target = tmp_path / "S" / "v1"
    shutil.copytree(DATASET, target)
    victim = sorted((target / "envelopes").iterdir())[0]
    doc = json.loads(victim.read_bytes())
    doc["transactions"][0]["request"]["path"] = "/x?y=1"
    victim.write_bytes(json.dumps(doc).encode())
    with pytest.raises(DatasetRejected):
        score(target, _run(_correct()))


def test_harness_refuses_labels_pointing_nowhere(tmp_path):
    def break_anchor(doc):
        next(x for x in doc["labels"] if x["label_status"] == "labeled_positive")["anchors"] = [
            {"locus": "req_header", "name": "x-not-there"}]
    with pytest.raises(DatasetRejected):
        score(_copy_with_labels(tmp_path, break_anchor), _run(_correct()))


def test_prediction_interface_is_strict():
    with pytest.raises(ValidationError):
        PredictionRun.model_validate_json(json.dumps({"run_meta": {"split": "dev", "model_id": "m", "prompt_version": "p",
                                                                   "ruleset_version": "r", "extra": 1}, "results": {}}))


# ── label_isolation: 엔진이 라벨을 읽지 않음(정적 범위) ─────────────────────────

def test_engine_has_no_label_path_or_label_types():
    assert [v.render() for v in scan_package(ENGINE_ROOT) if v.kind == LABELS] == []


@pytest.mark.parametrize("src", [
    'open("datasets/S/v1/labels.json").read()',
    'from pathlib import Path\nPath("x").joinpath("labels.json").read_bytes()',
    'ROOT = "../../datasets"',
    "from tools.dataset.labelfile import LabelFile",
    "from tools.dataset import labelfile\nx = labelfile.LabelFile",
    "def load(m):\n    return m.LabelFile",
])
def test_planted_label_read_in_engine_is_caught(tmp_path, src):
    root = tmp_path / "engine"
    root.mkdir()
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "planted.py").write_text(src + "\n", encoding="utf-8")
    assert LABELS in {v.kind for v in scan_package(root)}


def test_label_isolation_static_limits_are_pinned():
    """정직한 한계: 독스트링 언급은 읽기 경로가 아니라 제외하고, 런타임 조립 경로는 정적으로 못 잡는다(범위 밖)."""
    assert scan_source("d.py", 'def f():\n    """datasets/labels.json 형식 설명"""\n    return 1\n') == []
    assert scan_source("r.py", 'p = "data" + "sets"\nq = "labels" + ".json"\n') == []


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "eval_harness_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_eval_harness.py::"
_H = ("tools/eval/harness.py", "tools.eval.harness")
_A = ("tools/arch_boundary.py", "tools.arch_boundary")
MUTATIONS = {
    "category_condition_off": (*_H, "    return p.category in v.label.categories and bool(p.cnas & v.anchors)\n",
                               "    return bool(p.cnas & v.anchors)\n",
                               [_T + "test_right_location_wrong_category_counts_only_in_location_metrics_and_confusion"]),
    "anchor_overlap_off": (*_H, "    return p.category in v.label.categories and bool(p.cnas & v.anchors)\n",
                           "    return p.category in v.label.categories\n",
                           [_T + "test_right_category_wrong_location_is_tp_nowhere"]),
    # 1:1은 '확정 수 + 남은 최대 == 전체 최대' 검사가 구조적으로 강제한다 — used 건너뛰기만 끈 변이, 쓰인 라벨 금지만
    # 없앤 변이는 둘 다 살아남았다(같음 검사가 재사용 쌍을 확정하지 않음). 그래서 라벨 재사용을 허용하는 배정으로 통째로 바꾼다.
    "one_to_one_off": (*_H, "        for v in adj[p]:\n            if v in used:\n",
                       "        if adj[p]:  # 변이: 매칭 가능한 첫 라벨에 재사용 허용으로 붙임(1:1 해제)\n"
                       "            chosen[p] = adj[p][0]\n        for v in []:\n            if v in used:\n",
                       [_T + "test_left_over_duplicate_after_one_to_one_matching_is_fp"]),
    "greedy_matching": (*_H, "            if len(chosen) + 1 + rest == target:  # 이 쌍을 확정해도 최대가 유지될 때만\n",
                        "            if True:\n",
                        [_T + "test_maximum_matching_takes_both_where_greedy_would_take_one"]),
    "dedup_off": (*_H, "        groups.setdefault((p.category, p.cnas), []).append(p)\n",
                  "        groups.setdefault((p.category, p.cnas, p.finding_id), []).append(p)\n",
                  [_T + "test_exact_duplicates_are_merged_before_scoring"]),
    "sort_off": (*_H, "    preds = sorted((min(g, key=lambda q: q.key) for g in groups.values()), key=lambda q: q.key)\n",
                 "    preds = [g[0] for g in groups.values()]\n",
                 [_T + "test_tie_is_broken_by_the_sort_keys_and_is_deterministic_under_input_reordering"]),
    "j8_off": (*_H, "    if half > MAX_HALF_WIDTH:\n", "    if False:\n",
               [_T + "test_j8_small_samples_get_no_point_estimate", _T + "test_unimplemented_metrics_are_reported_honestly"]),
    "label_path_check_off": (*_A, '            self._add(node, LABELS, "라벨 경로 문자열")  # 값 자체는 남기지 않는다\n',
                             "            pass\n", [_T + "test_planted_label_read_in_engine_is_caught"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_harness_rule_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", rel, old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
