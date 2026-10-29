"""평가 데이터셋 S v1 첫 동결 — `dataset_version_freeze` · `dataset_engine_regression` · `dataset_mode_consistency` + 라벨 무결성.
(A) §2 버전 규칙(첫 소비자), §2.3 모드 규칙, §6.1·§6.2 라벨·동결.

동결 자산(`datasets/S/v1`)을 현재 코드로 다시 읽어 지킨다: 현재 스키마로 읽히는가(아니면 버전을 올렸는가), 엔진의 실제 ②③을
통과하는가(모드 무관 — 엔진 ③은 모드를 모른다), 기록된 마스킹 모드와 라벨 형태가 맞는가, 라벨 anchor가 실제 위치를
가리키는가(출력 게이트의 공개 `resolves` — 예측 evidence와 같은 정의). '위조 거부'로: 없는 위치를 가리키는 라벨, 상태 제약
위반, 스키마를 바꾸고 버전을 그대로 둔 모의, 엔진을 통과하지 못하게 손상된 Envelope, 모드 기록과 어긋나는 라벨을 잡는다.
원본(RawTransaction)은 동결에 없다(ⓕ). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

import tools.dataset.build_s_v1 as build_mod
import tools.dataset.freeze as freeze
from sentinel.pipeline import schema_gate
from tools.dataset.labelfile import LabelFile, anchor_problems
from tools.fixture_masker.raw import RawEnvelope
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "datasets" / "S" / "v1"


def _label_file(dataset: Path = DATASET) -> LabelFile:
    return LabelFile.model_validate_json((dataset / "labels.json").read_bytes())


def _transactions(dataset: Path = DATASET) -> dict:
    return {e.transactions[0].meta.transaction_id: e.transactions[0]
            for e in (schema_gate.parse_envelope(d) for d in freeze.envelope_files(dataset).values())}


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "S" / "v1"
    shutil.copytree(DATASET, target)
    return target


def _relation_ref(dataset: Path = DATASET) -> str:
    modes = json.loads((dataset / "labels.json").read_bytes())["frozen_against"]["masking_modes"]
    return next(k for k, v in modes.items() if v == "relation_preserving")


# ── 대조: 동결 자산이 현재 코드에서 성립 ──────────────────────────────────

def test_frozen_dataset_reads_under_current_schemas_and_records_them():
    label_file = _label_file()
    against = label_file.frozen_against.model_dump(exclude={"masking_modes"})
    assert against == freeze.current_versions()
    assert freeze.version_freeze_problems(DATASET) == []
    assert set(label_file.frozen_against.masking_modes) == set(_transactions())


def test_frozen_label_anchors_resolve_in_their_envelopes():
    assert anchor_problems(_label_file(), _transactions()) == []


def test_frozen_envelopes_pass_the_real_engine():
    assert freeze.engine_regression_problems(DATASET) == []


def test_frozen_envelopes_match_their_recorded_masking_modes():
    assert freeze.mode_problems(DATASET) == []


def test_first_freeze_covers_the_minimum_structure():
    labels = _label_file().labels
    modes = _label_file().frozen_against.masking_modes
    positive = [x for x in labels if x.label_status == "labeled_positive"]
    assert {c for x in positive for c in x.categories} == {"access_control", "info_exposure", "security_misconfig",
                                                          "reflected_injection_indicator"}
    assert any(x.label_status == "verified_clean" and not x.hard_negative for x in labels)
    assert any(x.hard_negative for x in labels)
    idor = [x for x in positive if modes[x.transaction_ref] == "relation_preserving"]
    assert idor and all({a.locus for a in x.anchors} >= {"req_header", "resp_body"} for x in idor)
    assert all(x.source == "construction" for x in labels)


def test_frozen_files_hold_no_raw_transaction_or_n5_markers():
    blobs = [*freeze.envelope_files(DATASET).values(), (DATASET / "labels.json").read_bytes()]
    assert not any(b"faketoken" in b or b"example.test" in b for b in blobs)
    for data in freeze.envelope_files(DATASET).values():
        with pytest.raises(ValidationError):
            RawEnvelope.model_validate_json(data)


# ── 위조 거부: 라벨 무결성 ─────────────────────────────────────────────

def _with_anchor(anchor: dict) -> LabelFile:
    doc = json.loads((DATASET / "labels.json").read_bytes())
    positive = next(x for x in doc["labels"] if x["label_status"] == "labeled_positive")
    positive["anchors"] = [anchor]
    return LabelFile.model_validate_json(json.dumps(doc))


@pytest.mark.parametrize("anchor", [
    {"locus": "req_header", "name": "x-not-there"},
    {"locus": "resp_body", "body": {"kind": "json", "path": "/no/such/node"}},
    {"locus": "req_param", "location": "form", "name": "q"},
    {"locus": "resp_header", "name": "content-type", "occurrence": 3},
    {"locus": "req_line", "part": "path", "range": {"start": 0, "end": 999}},
])
def test_label_anchor_pointing_nowhere_is_rejected(anchor):
    problems = anchor_problems(_with_anchor(anchor), _transactions())
    assert any(p.startswith("anchor_unresolvable@") for p in problems)


def test_label_for_missing_transaction_is_rejected():
    doc = json.loads((DATASET / "labels.json").read_bytes())
    txs = _transactions()
    txs.pop(UUID(doc["labels"][0]["transaction_ref"]))
    assert "transaction_missing@labels[0]" in anchor_problems(_label_file(), txs)


@pytest.mark.parametrize("anchor", [{"locus": "req_cookie", "name": "sid"}, {"locus": "resp_body", "body": {"kind": "xml"}},
                                    {"locus": "req_param", "location": "json", "name": "q"}, "req_header"])
def test_malformed_anchor_is_rejected_by_the_label_schema(anchor):
    with pytest.raises(ValidationError):
        _with_anchor(anchor)


@pytest.mark.parametrize("edit", ["positive_without_anchors", "positive_without_categories", "positive_hard_negative",
                                  "clean_with_anchors", "clean_with_category_not_hard_negative",
                                  "hard_negative_without_category", "unlabeled_with_category", "duplicate_category",
                                  "mode_missing_for_a_label", "unknown_source"])
def test_label_status_constraints_are_enforced(edit):
    doc = json.loads((DATASET / "labels.json").read_bytes())
    pos = next(x for x in doc["labels"] if x["label_status"] == "labeled_positive")
    clean = next(x for x in doc["labels"] if x["label_status"] == "verified_clean" and not x["hard_negative"])
    hard = next(x for x in doc["labels"] if x["hard_negative"])
    {"positive_without_anchors": lambda: pos.update(anchors=[]),
     "positive_without_categories": lambda: pos.update(categories=[]),
     "positive_hard_negative": lambda: pos.update(hard_negative=True),
     "clean_with_anchors": lambda: clean.update(anchors=[{"locus": "resp_status"}]),
     "clean_with_category_not_hard_negative": lambda: clean.update(categories=["info_exposure"]),
     "hard_negative_without_category": lambda: hard.update(categories=[]),
     "unlabeled_with_category": lambda: clean.update(label_status="unlabeled", categories=["info_exposure"]),
     "duplicate_category": lambda: pos.update(categories=pos["categories"] * 2),
     "mode_missing_for_a_label": lambda: doc["frozen_against"]["masking_modes"].pop(pos["transaction_ref"]),
     "unknown_source": lambda: pos.update(source="guess")}[edit]()
    with pytest.raises(ValidationError):
        LabelFile.model_validate_json(json.dumps(doc))


def test_builder_refuses_to_freeze_a_label_that_points_nowhere(tmp_path, monkeypatch):
    real = build_mod.cases

    def bad_cases():
        specs = real()
        specs[0]["label"] = {**specs[0]["label"], "anchors": [{"locus": "req_header", "name": "x-not-there"}]}
        return specs
    monkeypatch.setattr(build_mod, "cases", bad_cases)
    out = tmp_path / "S" / "v1"
    problems = build_mod.build(out)
    assert any(p.startswith("anchor_unresolvable@") for p in problems) and not out.exists()


def test_builder_never_overwrites_a_frozen_dataset(tmp_path):
    target = _copy(tmp_path)
    before = {p.name: p.read_bytes() for p in (target / "envelopes").iterdir()}
    assert build_mod.build(target) == ["dataset_exists"]
    assert {p.name: p.read_bytes() for p in (target / "envelopes").iterdir()} == before


# ── 위조 거부: 스키마 변경 + 버전 그대로 ──────────────────────────────────

def test_envelope_schema_change_without_version_bump_is_caught(tmp_path, monkeypatch):
    def stricter(raw):  # 모의: 현재 Envelope 스키마가 바뀌어 동결 데이터가 더는 읽히지 않음
        raise schema_gate.SchemaRejected(("simulated_schema_change",))
    monkeypatch.setattr(freeze.schema_gate, "parse_envelope", stricter)
    assert "envelope_schema_changed_without_version_bump" in freeze.version_freeze_problems(DATASET)
    monkeypatch.setattr(freeze, "current_versions",
                        lambda: {"envelope_schema": "2.0", "raw_schema": "1.0", "labelfile_schema": "1.0"})
    assert "envelope_schema_changed_without_version_bump" not in freeze.version_freeze_problems(DATASET)


def test_labelfile_schema_change_without_version_bump_is_caught(monkeypatch):
    class Stricter(LabelFile):  # 모의: 라벨 파일 스키마에 필수 필드가 생김
        reviewer: str
    monkeypatch.setattr(freeze, "LabelFile", Stricter)
    assert freeze.version_freeze_problems(DATASET) == ["labelfile_schema_changed_without_version_bump"]
    monkeypatch.setattr(freeze, "current_versions",
                        lambda: {"envelope_schema": "1.0", "raw_schema": "1.0", "labelfile_schema": "1.1"})
    assert freeze.version_freeze_problems(DATASET) == []


# ── 위조 거부: 엔진 회귀 ───────────────────────────────────────────────

def _tamper_first_strict(dataset: Path, edit) -> None:
    modes = json.loads((dataset / "labels.json").read_bytes())["frozen_against"]["masking_modes"]
    name = next(f"{k}.json" for k, v in modes.items() if v == "strict_redaction")
    path = dataset / "envelopes" / name
    doc = json.loads(path.read_bytes())
    edit(doc["transactions"][0])
    path.write_bytes(json.dumps(doc).encode())


def test_engine_regression_catches_a_frozen_envelope_the_engine_would_reject(tmp_path):
    target = _copy(tmp_path)
    jwt = "eyJ" + "h" * 12 + "." + "eyJ" + "p" * 12 + "." + "s" * 16
    _tamper_first_strict(target, lambda tx: tx["response"]["body"].update(content=json.dumps({"note": jwt})))
    problems = freeze.engine_regression_problems(target)
    assert len(problems) == 1 and problems[0].startswith("sanitization_rejected:jwt@")


def test_engine_regression_catches_a_schema_broken_envelope(tmp_path):
    target = _copy(tmp_path)
    _tamper_first_strict(target, lambda tx: tx["request"].update(path="/rest/x?y=1"))
    problems = freeze.engine_regression_problems(target)
    assert len(problems) == 1 and problems[0].startswith("schema_rejected:")


# ── 위조 거부: 모드 정합 ───────────────────────────────────────────────

def test_relation_envelope_recorded_as_strict_is_caught(tmp_path):
    target = _copy(tmp_path)
    doc = json.loads((target / "labels.json").read_bytes())
    doc["frozen_against"]["masking_modes"][_relation_ref(target)] = "strict_redaction"
    (target / "labels.json").write_bytes(json.dumps(doc).encode())
    assert [p.split("@")[0] for p in freeze.mode_problems(target)] == ["strict_with_label"]


def test_strict_envelope_recorded_as_relation_is_caught(tmp_path):
    target = _copy(tmp_path)
    doc = json.loads((target / "labels.json").read_bytes())
    ref = next(k for k, v in doc["frozen_against"]["masking_modes"].items() if v == "strict_redaction")
    doc["frozen_against"]["masking_modes"][ref] = "relation_preserving"
    (target / "labels.json").write_bytes(json.dumps(doc).encode())
    assert [p.split("@")[0] for p in freeze.mode_problems(target)] == ["relation_without_ref_label"]


def test_envelope_without_recorded_mode_is_caught(tmp_path):
    target = _copy(tmp_path)
    doc = json.loads((target / "labels.json").read_bytes())
    doc["frozen_against"]["masking_modes"].pop(_relation_ref(target))
    (target / "labels.json").write_bytes(json.dumps(doc).encode())
    assert [p.split("@")[0] for p in freeze.mode_problems(target)] == ["mode_not_recorded"]


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "dataset_freeze_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_dataset_freeze.py::"
_L = ("tools/dataset/labelfile.py", "tools.dataset.labelfile")
_F = ("tools/dataset/freeze.py", "tools.dataset.freeze")
MUTATIONS = {
    "anchor_resolve_off": (*_L, "            if not output_gate.resolves(anchor, tx):  # (나) 실제 위치\n", "            if False:\n",
                           [_T + "test_label_anchor_pointing_nowhere_is_rejected",
                            _T + "test_builder_refuses_to_freeze_a_label_that_points_nowhere"]),
    "anchor_type_off": (*_L, "    anchors: list[Locator]\n", "    anchors: list\n",
                        [_T + "test_malformed_anchor_is_rejected_by_the_label_schema"]),
    "version_bump_check_off": (*_F, '    if not envelopes_ok and frozen["envelope_schema"] == now["envelope_schema"]:\n',
                               "    if False:\n", [_T + "test_envelope_schema_change_without_version_bump_is_caught"]),
    "mode_record_ignored": (*_F, '        mode = modes.get(UUID(tx["meta"]["transaction_id"]))\n',
                            '        mode = "strict_redaction"  # 변이: 기록된 모드 무시\n',
                            [_T + "test_frozen_envelopes_match_their_recorded_masking_modes"]),
    "regression_uses_masker_self_check": (*_F, "        verdict, reasons = engine_verdict(data)\n",
        "        from tools.fixture_masker.masker import _spans_ok  # 변이: 엔진 대신 마스커 자체 검증\n"
        "        tx = json.loads(data)['transactions'][0]\n"
        "        ok = all(_spans_ok(tx[s]['body']) for s in ('request', 'response'))\n"
        "        verdict, reasons = ('accepted', ()) if ok else ('masker_rejected', ())\n",
        [_T + "test_engine_regression_catches_a_frozen_envelope_the_engine_would_reject"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_freeze_check_is_load_bearing_under_verified_mutation(tmp_path, name):
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
