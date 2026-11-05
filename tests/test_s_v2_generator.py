"""S v2 생성기 장치 — (A) §6.2 S v2 구성, §3.5 `dataset_case_independence`·`producer_freeze_order`·`guideline_freeze`.

합성 카탈로그로 증명한다. 사례 내용은 템플릿일 뿐이고 실제 S v2 카탈로그는 별도 작업이다. 게이트를 낮추는 인자가 없으므로
합성 카탈로그도 실제 게이트를 넘는 크기다.
"""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.pipeline import rule_engine
from tools.dataset import generator
from tools.dataset.generator import Catalog, build, catalog_problems
from tools.dataset.labelfile import LabelFile
from tools.eval import runner
from tools.eval.frozen_rulesets import FROZEN_GUIDELINES, FROZEN_RULESETS, current_ruleset_hash
from tools.eval.harness import OUT_OF_FREEZE_ORDER, DatasetRejected, PredictionRun, RunMeta, load_dataset, score
from tools.eval.runner import RunRejected
from tools.mutation_guard import copy_with_mutation
from tests.test_rule_wiring import _run_mutant

REPO_ROOT = Path(__file__).resolve().parents[1]
REFLECT = "reflected_injection_indicator"
EXPOSURE = "info_exposure"
MISCONFIG = "security_misconfig"
ACCESS = "access_control"
TRACE = "Traceback (most recent call last):"
Q = {"locus": "req_param", "location": "query", "name": "q"}
ACAO, ACAC = "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"


def _json_at(path: str) -> dict:
    return {"locus": "resp_body", "body": {"kind": "json", "path": path}}


def _header(name: str) -> dict:
    return {"locus": "resp_header", "name": name.lower()}


def _positive(category: str, anchors: list, clause: str) -> dict:
    return {"label_status": "labeled_positive", "categories": [category], "anchors": anchors, "clause": clause}


def _case(cid: str, method_path: str, pattern: str, split: str, labels: list, mode="strict_redaction", **tx) -> dict:
    return {"case_id": cid, "endpoint": {"method": "GET", "path_template": method_path}, "pattern_id": pattern, "split": split,
            "masking_mode": mode, "source": "construction", "labels": labels, "tx": {"path": method_path, **tx}}


def _reflect(split: str, i: int) -> dict:
    value = f"<b>{i}"
    return _case(f"{split}-ri-{i}", f"/{split}/search/{i}", "ri-raw", split,
                 [_positive(REFLECT, [Q, _json_at("/query")], "RI-P1")],
                 params=[{"name": "q", "value": value, "location": "query"}], resp_json={"query": value})


def _exposure(split: str, i: int) -> dict:
    return _case(f"{split}-ie-{i}", f"/{split}/error/{i}", "ie-trace", split, [_positive(EXPOSURE, [_json_at("/stack")], "IE-P1")],
                 status=500, resp_json={"stack": TRACE})


def _misconfig(split: str, i: int) -> dict:
    return _case(f"{split}-sm-{i}", f"/{split}/cors/{i}", "sm-wildcard", split,
                 [_positive(MISCONFIG, [_header(ACAO), _header(ACAC)], "SM-P1")], resp_json={"status": "ok"},
                 resp_headers=[{"name": ACAO, "value": "*"}, {"name": ACAC, "value": "true"}])


def _access(split: str, i: int) -> dict:
    return _case(f"{split}-ac-{i}", f"/{split}/basket/{i}", "ac-other-owner", split,
                 [_positive(ACCESS, [{"locus": "req_header", "name": "authorization"}, _json_at("/data/owner_token")], "AC-P1")],
                 mode="relation_preserving", headers=[{"name": "Authorization", "value": f"Bearer ${{tok:u_{split}_{i}}}"}],
                 resp_json={"data": {"owner_token": f"${{tok:o_{split}_{i}}}"}})


def _hard(split: str, category: str, clause: str, i: int) -> dict:
    return _case(f"{split}-hn-{category}-{i}", f"/{split}/hn/{category}/{i}", f"hn-{clause}", split,
                 [{"label_status": "verified_clean", "categories": [category], "anchors": [], "hard_negative": True,
                   "clause": clause}], resp_json={"status": "ok"})


def _clean(split: str, i: int) -> dict:
    return _case(f"{split}-clean-{i}", f"/{split}/clean/{i}", "clean", split,
                 [{"label_status": "verified_clean", "categories": [], "anchors": []}], resp_json={"status": "ok"})


def _doc() -> dict:
    cases = []
    for split, per_category, cleans in (("test", 10, 24), ("dev", 5, 20)):
        for i in range(per_category):
            cases += [_reflect(split, i), _exposure(split, i), _misconfig(split, i), _access(split, i)]
        cases += [_clean(split, i) for i in range(cleans)]
    for category, clause in ((REFLECT, "RI-N3"), (EXPOSURE, "IE-N1"), (MISCONFIG, "SM-N1"), (ACCESS, "AC-N1")):
        cases += [_hard("test", category, clause, i) for i in range(4)]
    two = next(c for c in cases if c["case_id"] == "test-ri-0")  # 결함 둘: 반사 + 스택 트레이스
    two["labels"].append(_positive(EXPOSURE, [_json_at("/stack")], "IE-P1"))
    two["tx"]["resp_json"]["stack"] = TRACE
    return {"dataset_id": "S-synthetic", "guideline": {"version": "v1", "hash": FROZEN_GUIDELINES["v1"]}, "cases": cases}


def _catalog(doc: dict | None = None) -> Catalog:
    return Catalog.model_validate_json(json.dumps(_doc() if doc is None else doc))


def _case_of(doc: dict, case_id: str) -> dict:
    return next(c for c in doc["cases"] if c["case_id"] == case_id)


@pytest.fixture(scope="module")
def dataset(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("s") / "S-synthetic"
    assert build(_catalog(), out) == []
    return out


# ── 정상 ───────────────────────────────────────────────────────────

def test_valid_catalog_passes_every_check():
    assert catalog_problems(_catalog()) == []


def test_generated_dataset_is_label_file_1_1_with_split_and_ruleset(dataset):
    label_file, txs = load_dataset(dataset)
    assert label_file.schema_version == "1.1" and label_file.split_scheme == "endpoint"
    assert label_file.frozen_against.ruleset_version == rule_engine.RULESET_VERSION
    assert label_file.frozen_against.ruleset_hash == current_ruleset_hash()
    assert len(txs) == len(_doc()["cases"]) and {x.split for x in label_file.labels} == {"dev", "test"}


def test_token_placeholders_do_not_survive_and_no_generated_token_is_written(dataset):
    data = b"".join(p.read_bytes() for p in dataset.rglob("*.json"))
    assert b"${tok:" not in data and b"faketoken_" not in data


def test_same_token_name_gives_the_same_relation_label_and_different_names_differ(tmp_path):
    doc = _doc()
    same = _case_of(doc, "test-ac-0")
    same["tx"]["resp_json"]["data"]["owner_token"] = "Bearer ${tok:u_test_0}"  # 라벨은 마스킹되는 값 전체로 정해진다
    out = tmp_path / "d"
    assert build(_catalog(doc), out) == []
    _label_file, txs = load_dataset(out)
    relation = [t for t in txs.values() if any(h.name == "Authorization" for h in t.request.headers)]
    pairs = {(next(h.value.label for h in t.request.headers if h.name == "Authorization"),
              t.response.body.masked_spans[0].ref.label) for t in relation}
    assert sum(a == b for a, b in pairs) == 1 and len(pairs) == 15


# ── 위조 거부: 동결 ────────────────────────────────────────────────

def test_wrong_guideline_hash_in_the_catalog_is_refused():
    doc = _doc()
    doc["guideline"]["hash"] = "0" * 64
    assert catalog_problems(_catalog(doc)) == ["guideline_not_frozen"]


def test_unknown_guideline_version_is_refused():
    doc = _doc()
    doc["guideline"]["version"] = "v0"
    assert catalog_problems(_catalog(doc)) == ["guideline_not_frozen"]


def test_changed_guideline_file_is_refused(tmp_path, monkeypatch):
    changed = tmp_path / "labeling-guideline.md"
    changed.write_text(generator.GUIDELINE_PATH.read_text(encoding="utf-8") + "추가\n", encoding="utf-8")
    monkeypatch.setattr(generator, "GUIDELINE_PATH", changed)
    assert "guideline_not_frozen" in catalog_problems(_catalog())


def test_unfrozen_ruleset_version_is_refused(monkeypatch):
    monkeypatch.setattr(rule_engine, "RULESET_VERSION", "rules-unfrozen")
    assert "ruleset_not_frozen" in catalog_problems(_catalog())


def test_changed_rule_files_are_refused(monkeypatch):
    monkeypatch.setattr(generator, "current_ruleset_hash", lambda: "0" * 64)
    assert "ruleset_not_frozen" in catalog_problems(_catalog())


def test_refused_catalog_writes_nothing(tmp_path):
    doc = _doc()
    doc["guideline"]["hash"] = "0" * 64
    out = tmp_path / "d"
    assert build(_catalog(doc), out) == ["guideline_not_frozen"]
    assert not out.exists()


def test_existing_dataset_is_never_overwritten(dataset):
    before = (dataset / "labels.json").read_bytes()
    assert build(_catalog(), dataset) == ["dataset_exists"]
    assert (dataset / "labels.json").read_bytes() == before


# ── 위조 거부: 구성 ────────────────────────────────────────────────

def test_duplicate_endpoint_and_pattern_is_refused():
    doc = _doc()
    _case_of(doc, "test-ri-1")["endpoint"] = copy.deepcopy(_case_of(doc, "test-ri-2")["endpoint"])
    assert catalog_problems(_catalog(doc)) == ["duplicate_endpoint_pattern"]


def test_same_endpoint_with_another_pattern_is_allowed():
    doc = _doc()
    case = _case_of(doc, "test-ri-1")
    case["endpoint"] = copy.deepcopy(_case_of(doc, "test-ri-2")["endpoint"])
    case["pattern_id"] = "ri-other"
    assert catalog_problems(_catalog(doc)) == []


def test_duplicate_case_id_is_refused():
    doc = _doc()
    _case_of(doc, "test-ri-1")["case_id"] = "test-ri-2"
    assert catalog_problems(_catalog(doc)) == ["duplicate_case_id"]


def test_endpoint_in_two_splits_is_refused():
    doc = _doc()
    case = _case_of(doc, "dev-clean-0")
    case["endpoint"] = copy.deepcopy(_case_of(doc, "test-clean-0")["endpoint"])
    case["pattern_id"] = "clean-other"
    assert catalog_problems(_catalog(doc)) == ["endpoint_in_two_splits"]


def _without(doc: dict, prefix: str) -> dict:
    doc["cases"] = [c for c in doc["cases"] if not c["case_id"].startswith(prefix)]
    return doc


def test_too_few_positive_transactions_in_test_is_refused():
    doc = _without(_doc(), "test-ie-")  # 40 → 30
    assert "scale_positive@test" in catalog_problems(_catalog(doc))


def test_too_few_clean_transactions_in_test_is_refused():
    assert "scale_clean@test" in catalog_problems(_catalog(_without(_doc(), "test-clean-")))


def test_too_few_positive_transactions_in_dev_is_refused():
    assert "scale_positive@dev" in catalog_problems(_catalog(_without(_doc(), "dev-ie-")))


def test_too_few_clean_transactions_in_dev_is_refused():
    assert "scale_clean@dev" in catalog_problems(_catalog(_without(_doc(), "dev-clean-")))


def test_positive_gate_counts_transactions_not_labels():
    """라벨을 늘려도 트랜잭션이 모자라면 미달이다."""
    doc = _without(_doc(), "test-ie-")
    for i in range(1, 10):
        _case_of(doc, f"test-ri-{i}")["labels"].append(_positive(EXPOSURE, [_json_at("/query")], "IE-P1"))
    assert "scale_positive@test" in catalog_problems(_catalog(doc))


def test_too_few_positive_transactions_of_a_category_is_refused():
    doc = _doc()
    doc["cases"] = [c for c in doc["cases"] if c["case_id"] not in {f"test-ac-{i}" for i in range(3)}]
    doc["cases"] += [_reflect("test", 100 + i) for i in range(3)]
    assert catalog_problems(_catalog(doc)) == [f"scale_category_positive@{ACCESS}"]


def test_too_few_hard_negative_transactions_of_a_category_is_refused():
    doc = _without(_doc(), f"test-hn-{REFLECT}")
    doc["cases"] += [_clean("test", 100 + i) for i in range(4)]
    assert catalog_problems(_catalog(doc)) == [f"scale_category_hard_negative@{REFLECT}"]


def test_unknown_clause_is_refused():
    doc = _doc()
    _case_of(doc, "test-ri-1")["labels"][0]["clause"] = "RI-P9"
    assert catalog_problems(_catalog(doc)) == ["clause_unknown"]


def test_hard_negative_without_a_clause_is_refused():
    doc = _doc()
    _case_of(doc, f"test-hn-{REFLECT}-0")["labels"][0]["clause"] = None
    assert catalog_problems(_catalog(doc)) == ["clause_unknown"]


def _origin_case(origin: str | None) -> dict:
    case = _case("test-sm-p2", "/test/origin", "sm-origin", "test",
                 [_positive(MISCONFIG, [{"locus": "req_header", "name": "origin"}, _header(ACAO), _header(ACAC)], "SM-P2")],
                 resp_json={"status": "ok"}, resp_headers=[{"name": ACAO, "value": origin or "x"}, {"name": ACAC, "value": "true"}])
    if origin is not None:
        case["tx"]["headers"] = [{"name": "Origin", "value": origin}]
    return case


def test_origin_case_with_a_foreign_host_passes():
    doc = _doc()
    doc["cases"].append(_origin_case("https://a.example.test"))
    assert catalog_problems(_catalog(doc)) == []


@pytest.mark.parametrize("origin", [None, "", f"https://{generator.REQUEST_HOST}", f"http://{generator.REQUEST_HOST}:3000"],
                         ids=["missing", "empty", "same_host", "same_host_with_port"])
def test_origin_case_breaking_the_construction_condition_is_refused(origin):
    doc = _doc()
    doc["cases"].append(_origin_case(origin))
    assert catalog_problems(_catalog(doc)) == ["construction@SM-P2"]


def _hsts_case(label: dict, scheme: str) -> dict:
    return _case("test-hsts", "/test/hsts", "sm-hsts", "test", [label], scheme=scheme, resp_json={"status": "ok"},
                 resp_headers=[{"name": "Strict-Transport-Security", "value": "max-age=0"}])


HSTS_LABELS = {"SM-P4": _positive(MISCONFIG, [_header("Strict-Transport-Security")], "SM-P4"),
               "SM-N3": {"label_status": "verified_clean", "categories": [MISCONFIG], "anchors": [], "hard_negative": True,
                         "clause": "SM-N3"}}


@pytest.mark.parametrize("clause", sorted(HSTS_LABELS))
def test_hsts_case_over_https_passes(clause):
    doc = _doc()
    doc["cases"].append(_hsts_case(HSTS_LABELS[clause], "https"))
    assert catalog_problems(_catalog(doc)) == []


@pytest.mark.parametrize("clause", sorted(HSTS_LABELS))
def test_hsts_case_over_http_is_refused(clause):
    doc = _doc()
    doc["cases"].append(_hsts_case(HSTS_LABELS[clause], "http"))
    assert catalog_problems(_catalog(doc)) == [f"construction@{clause}"]


def test_hard_negative_on_a_positive_transaction_is_refused(tmp_path):
    doc = _doc()
    _case_of(doc, "test-ri-1")["labels"][0]["hard_negative"] = True
    out = tmp_path / "d"
    assert build(_catalog(doc), out) == ["labelfile_invalid"] and not out.exists()


def test_clean_label_next_to_another_label_is_refused(tmp_path):
    doc = _doc()
    _case_of(doc, "test-ri-1")["labels"].append({"label_status": "verified_clean", "categories": [], "anchors": []})
    out = tmp_path / "d"
    assert build(_catalog(doc), out) == ["labelfile_invalid"] and not out.exists()


def test_anchor_that_does_not_resolve_is_refused(tmp_path):
    doc = _doc()
    _case_of(doc, "test-ri-1")["labels"][0]["anchors"] = [_json_at("/nowhere")]
    out = tmp_path / "d"
    assert build(_catalog(doc), out) == ["anchor_unresolvable@labels[" + _label_index(doc, "test-ri-1") + "].anchors[0]"]


def _label_index(doc: dict, case_id: str) -> str:
    index = 0
    for c in doc["cases"]:
        if c["case_id"] == case_id:
            return str(index)
        index += len(c["labels"])
    raise AssertionError(case_id)


# ── LabelFile 1.1 / 1.0 ────────────────────────────────────────────

def _label_doc(dataset: Path) -> dict:
    return json.loads((dataset / "labels.json").read_bytes())


def _read(doc: dict) -> LabelFile:
    return LabelFile.model_validate_json(json.dumps(doc))


def test_label_with_a_missing_split_is_an_error_not_null(dataset):
    doc = _label_doc(dataset)
    refs = [x["transaction_ref"] for x in doc["labels"]]
    del next(x for x in doc["labels"] if refs.count(x["transaction_ref"]) == 1)["split"]
    with pytest.raises(ValidationError):
        _read(doc)


def test_split_without_a_scheme_is_refused(dataset):
    doc = _label_doc(dataset)
    del doc["split_scheme"]
    with pytest.raises(ValidationError):
        _read(doc)


def test_two_labels_of_a_transaction_cannot_disagree_on_split(dataset):
    doc = _label_doc(dataset)
    refs = [x["transaction_ref"] for x in doc["labels"]]
    twin = next(x for x in doc["labels"] if refs.count(x["transaction_ref"]) == 2)
    twin["split"] = "dev"
    with pytest.raises(ValidationError):
        _read(doc)


@pytest.mark.parametrize("field", ["ruleset_version", "ruleset_hash"])
def test_1_1_requires_the_ruleset_record(dataset, field):
    doc = _label_doc(dataset)
    del doc["frozen_against"][field]
    with pytest.raises(ValidationError):
        _read(doc)


def test_1_1_clean_label_must_be_alone(dataset):
    doc = _label_doc(dataset)
    extra = copy.deepcopy(next(x for x in doc["labels"] if x["label_status"] == "verified_clean"))
    extra.update(label_status="labeled_positive", categories=[REFLECT], hard_negative=False,
                 anchors=[{"locus": "resp_status"}])
    doc["labels"].append(extra)
    with pytest.raises(ValidationError):
        _read(doc)


def test_hard_negative_flag_on_a_positive_label_is_refused(dataset):
    doc = _label_doc(dataset)
    next(x for x in doc["labels"] if x["label_status"] == "labeled_positive")["hard_negative"] = True
    with pytest.raises(ValidationError):
        _read(doc)


S_V1 = REPO_ROOT / "datasets" / "S" / "v1"


def test_s_v1_still_reads_as_1_0():
    label_file, _txs = load_dataset(S_V1)
    assert label_file.schema_version == "1.0" and label_file.split_scheme is None
    assert all(x.split is None for x in label_file.labels) and label_file.frozen_against.ruleset_version is None


@pytest.mark.parametrize("edit", [lambda d: d["labels"].append(copy.deepcopy(d["labels"][0])),
                                  lambda d: d["labels"][0].update(split="dev"),
                                  lambda d: d.update(split_scheme="endpoint"),
                                  lambda d: d["frozen_against"].update(ruleset_version="rules-2")],
                         ids=["two_labels", "split", "split_scheme", "ruleset_record"])
def test_1_0_stays_one_label_per_transaction_without_new_fields(edit):
    doc = _label_doc(S_V1)
    edit(doc)
    with pytest.raises(ValidationError):
        _read(doc)


# ── 하네스·러너 ────────────────────────────────────────────────────

def test_split_dataset_needs_the_split_argument(dataset):
    with pytest.raises(RunRejected, match="split_required"):
        runner.run(dataset, {})


def test_only_the_chosen_split_is_scored(dataset):
    test, dev = runner.run(dataset, {}, "test"), runner.run(dataset, {}, "dev")
    assert test["header"]["split"] == "test" and dev["header"]["split"] == "dev"
    assert test["J2"]["rejection_rate"]["n"] == 80 and dev["J2"]["rejection_rate"]["n"] == 40


def test_both_labels_right_gives_two_true_positives(dataset):
    report = runner.run(dataset, {}, "test")
    counts = {ref: report["matches"].count(ref) for ref in report["matches"]}
    assert sorted(counts.values())[-1] == 2 and list(counts.values()).count(2) == 1
    assert report["duplicates"]["left_over_fp"] == 0


def test_multi_label_transactions_are_reported(dataset):
    assert runner.run(dataset, {}, "test")["J1"]["multi_label_transactions"] == 1
    assert runner.run(dataset, {}, "dev")["J1"]["multi_label_transactions"] == 0


def test_s_v1_has_no_multi_label_transactions():
    assert runner.run(S_V1, {})["J1"]["multi_label_transactions"] == 0


def _hand_run(split: str | None, results: dict) -> PredictionRun:
    return PredictionRun(run_meta=RunMeta(split=split, pipeline_mode="rule_only", model_id=None, prompt_version=None,
                                          ruleset_version=rule_engine.RULESET_VERSION), results=results)


def test_score_refuses_a_split_dataset_without_a_split(dataset):
    with pytest.raises(DatasetRejected, match="split_required"):
        score(dataset, _hand_run(None, {}))


def test_score_refuses_results_outside_the_chosen_split(dataset):
    with pytest.raises(DatasetRejected, match="results_differ_from_split"):
        score(dataset, _hand_run("test", {}))


def test_run_on_the_recorded_ruleset_is_a_measurement(dataset):
    assert runner.run(dataset, {}, "test")["header"]["freeze_order"] is None


def test_test_split_on_another_ruleset_is_marked_out_of_freeze_order(dataset, monkeypatch):
    monkeypatch.setattr(rule_engine, "RULESET_VERSION", "rules-3")
    assert runner.run(dataset, {}, "test")["header"]["freeze_order"] == OUT_OF_FREEZE_ORDER == "동결 순서 밖 — 측정 아님"


def test_dev_split_on_another_ruleset_is_not_marked(dataset, monkeypatch):
    monkeypatch.setattr(rule_engine, "RULESET_VERSION", "rules-3")
    assert runner.run(dataset, {}, "dev")["header"]["freeze_order"] is None


def test_recorded_hash_that_differs_from_the_frozen_table_is_marked(dataset, tmp_path):
    copied = tmp_path / "copy"
    shutil.copytree(dataset, copied)
    doc = _label_doc(copied)
    doc["frozen_against"]["ruleset_hash"] = "0" * 64
    (copied / "labels.json").write_text(json.dumps(doc), encoding="utf-8")
    assert runner.run(copied, {}, "test")["header"]["freeze_order"] == OUT_OF_FREEZE_ORDER


def test_frozen_table_holds_the_recorded_version():
    assert rule_engine.RULESET_VERSION in FROZEN_RULESETS


# ── 변이 확인 ──────────────────────────────────────────────────────

_G = "tests/test_s_v2_generator.py::"
GEN = ("tools/dataset/generator.py", "tools.dataset.generator")
LAB = ("tools/dataset/labelfile.py", "tools.dataset.labelfile")
HAR = ("tools/eval/harness.py", "tools.eval.harness")
RUN = ("tools/eval/runner.py", "tools.eval.runner")
MUTATIONS = {
    "guideline_check_off": (*GEN, "    if FROZEN_GUIDELINES.get(ref.version) != ref.hash or not guideline_is_frozen(GUIDELINE_PATH, ref.version):\n",
                            "    if False:\n", [_G + "test_wrong_guideline_hash_in_the_catalog_is_refused",
                                                _G + "test_changed_guideline_file_is_refused"]),
    "guideline_file_not_compared": (*GEN, " or not guideline_is_frozen(GUIDELINE_PATH, ref.version):\n", ":\n",
                                    [_G + "test_changed_guideline_file_is_refused"]),
    "ruleset_check_off": (*GEN, "    if FROZEN_RULESETS.get(rule_engine.RULESET_VERSION) != current_ruleset_hash():\n", "    if False:\n",
                          [_G + "test_unfrozen_ruleset_version_is_refused", _G + "test_changed_rule_files_are_refused"]),
    "independence_off": (*GEN, '(["duplicate_endpoint_pattern"] if max(pairs.values(), default=0) > 1 else [])', "[]",
                         [_G + "test_duplicate_endpoint_and_pattern_is_refused"]),
    "endpoint_split_off": (*GEN, "any(len(s) > 1 for s in splits.values())", "False", [_G + "test_endpoint_in_two_splits_is_refused"]),
    "positive_gate_off": (*GEN, "        if sum(_is_positive(c) for c in cases) < positives:\n", "        if False:\n",
                          [_G + "test_too_few_positive_transactions_in_test_is_refused",
                           _G + "test_too_few_positive_transactions_in_dev_is_refused"]),
    "positive_gate_counts_labels": (*GEN, "        if sum(_is_positive(c) for c in cases) < positives:\n",
                                    "        if sum(len(c.labels) for c in cases) < positives:\n",
                                    [_G + "test_positive_gate_counts_transactions_not_labels"]),
    "clean_gate_off": (*GEN, "        if sum(_is_clean(c) for c in cases) < cleans:\n", "        if False:\n",
                       [_G + "test_too_few_clean_transactions_in_test_is_refused",
                        _G + "test_too_few_clean_transactions_in_dev_is_refused"]),
    "category_gate_off": (*GEN, "        if positive < CATEGORY_GATE[0]:\n", "        if False:\n",
                          [_G + "test_too_few_positive_transactions_of_a_category_is_refused"]),
    "hard_negative_counts_positives": (*GEN, "_is_clean(c) and c.labels[0].hard_negative and category in c.labels[0].categories",
                                       "category in c.labels[0].categories",
                                       [_G + "test_too_few_hard_negative_transactions_of_a_category_is_refused"]),
    "clause_off": (*GEN, '                if label.clause is None or f"- **{label.clause} " not in text:\n', "                if False:\n",
                   [_G + "test_unknown_clause_is_refused", _G + "test_hard_negative_without_a_clause_is_refused"]),
    "construction_off": (*GEN, "            if check is not None and not check(c):\n", "            if False:\n",
                         [_G + "test_origin_case_breaking_the_construction_condition_is_refused[same_host]"]),
    "https_condition_off": (*GEN, 'CONSTRUCTION_CHECKS: Final = {"SM-P2": _origin_is_foreign, "SM-P4": _is_https, "SM-N3": _is_https}',
                            'CONSTRUCTION_CHECKS: Final = {"SM-P2": _origin_is_foreign}',
                            [_G + "test_hsts_case_over_http_is_refused[SM-P4]", _G + "test_hsts_case_over_http_is_refused[SM-N3]"]),
    "overwrite_allowed": (*GEN, "    if out_dir.exists():\n        return [\"dataset_exists\"]\n", "",
                          [_G + "test_existing_dataset_is_never_overwritten"]),
    "split_may_be_missing": (*LAB, "        if self.split_scheme is not None and any(label.split is None for label in self.labels):\n",
                             "        if False:\n", [_G + "test_label_with_a_missing_split_is_an_error_not_null"]),
    "clean_may_share": (*LAB, '            if len(group) > 1 and any(label.label_status != "labeled_positive" for label in group):\n',
                        "            if False:\n", [_G + "test_1_1_clean_label_must_be_alone",
                                                    _G + "test_clean_label_next_to_another_label_is_refused"]),
    "ruleset_record_optional": (*LAB, "        if self.frozen_against.ruleset_version is None or self.frozen_against.ruleset_hash is None:\n",
                                "        if False:\n", [_G + "test_1_1_requires_the_ruleset_record[ruleset_version]"]),
    "1_0_may_have_two_labels": (*LAB, "        if any(len(g) != 1 for g in groups.values()):\n", "        if False:\n",
                                [_G + "test_1_0_stays_one_label_per_transaction_without_new_fields[two_labels]"]),
    "score_ignores_split": (*HAR, "    labels = [label for label in label_file.labels if label.split == run.run_meta.split]\n",
                            "    labels = label_file.labels\n", [_G + "test_only_the_chosen_split_is_scored"]),
    "freeze_order_off": (*HAR, "    return None if same and llm_frozen else OUT_OF_FREEZE_ORDER\n", "    return None\n",
                         [_G + "test_test_split_on_another_ruleset_is_marked_out_of_freeze_order",
                          _G + "test_recorded_hash_that_differs_from_the_frozen_table_is_marked"]),
    "freeze_order_on_dev_too": (*HAR, '    if run_meta.split != "test":\n        return None\n', "",
                                [_G + "test_dev_split_on_another_ruleset_is_not_marked"]),
    "split_argument_optional": (*RUN, '    if split is None:\n        raise RunRejected("split_required")\n', "",
                                [_G + "test_split_dataset_needs_the_split_argument"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_generator_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools", "docs"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
