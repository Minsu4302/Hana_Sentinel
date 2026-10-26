"""출력 스키마 게이트 — `evidence_min_one` · `evidence_ref_integrity` · `server_assigned_status` ·
`category_closed_enum`(→ `output_schema_gate` 파생). (A) §2.4 출력 검증 규칙, §3.5.

'위조 거부'로 증명한다: 서버 부여 필드 주입, 4종 밖 category(표기 변형 포함), evidence 0개, analyzed_refs 밖 참조,
형 변환 우회, 부분 위반이 모두 OutputRejection(결과 전체 폐기)으로 끝나고, 감사에는 사유 코드만 남는다.
대조: 정상 초안은 서버 부여 값이 정확히 정해진 값으로 채워진 AnalysisResult가 된다.
변이 확인은 tools.mutation_guard로 '치환 성공 + 실행 중 로드된 모듈 = 변이본'을 먼저 증명한다.

범위((A) §3.5 각주): 검증 함수 단위(주입 테스트). 파이프라인 ④ 결선은 LLM 연동 PR에서 별도 증명.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

import sentinel.pipeline.output_gate as gate
from sentinel.audit import attach_audit_store, detach_audit_store, read_audit_events
from sentinel.output_schema import SERVER_ASSIGNED_FIELDS, AnalysisDraft, AnalysisMeta, AnalysisResult, Finding
from sentinel.pipeline.output_gate import REASON_CODES, OutputRejection
from tests.test_auth import PIPELINE_FUNCTIONS
from tools.mutation_guard import MutationNotApplied, assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
REF = uuid.UUID("00000000-0000-4000-8000-0000000000a1")
OTHER_REF = uuid.UUID("00000000-0000-4000-8000-0000000000b2")
META = AnalysisMeta(model_id="dummy-model", policy_version="p1", prompt_version="v1", ruleset_version="r0",
                    elapsed_ms=12, pipeline_mode="test", manifest_snapshot={})


def _evidence(ref: uuid.UUID = REF) -> dict:
    return {"transaction_ref": str(ref), "locus": "resp_body", "pointer": "$.user.email",
            "observation": "응답 본문에 이메일 필드가 있음(가명 라벨 ref_01)"}


def _finding(**over) -> dict:
    f = {"category": "info_exposure", "hypothesis": "개인정보가 노출됐을 가능성", "evidence": [_evidence()],
         "claim_basis": "observed", "limitations": [], "next_steps": [
             {"type": "verification", "action": "Burp에서 다른 계정으로 재현", "rationale": "응답 범위 확인"}]}
    f.update(over)
    return f


def _advisory(**over) -> dict:
    a = {"type": "out_of_scope_advisory", "topic": "csrf", "basis": [_evidence()], "suggestion": "수동 점검 권고"}
    a.update(over)
    return a


def _draft(findings=None, advisories=None) -> dict:
    return {"findings": [_finding()] if findings is None else findings,
            "advisory_signals": [_advisory()] if advisories is None else advisories}


def _run_gate(draft, refs=(REF,), produced_by="llm"):
    raw = draft if isinstance(draft, (bytes, str)) else json.dumps(draft, ensure_ascii=False)
    return gate.validate_draft(raw, analyzed_refs=list(refs), produced_by=produced_by, analysis_meta=META)


def _rejected(result, *codes: str) -> None:
    assert isinstance(result, OutputRejection), f"거부되지 않음: {type(result).__name__}"
    assert result.reason_codes == tuple(sorted(codes))


# ── 대조: 정상 초안 → 서버 부여 값이 정확히 일치 ────────────────────────

def test_valid_draft_gets_exactly_the_server_assigned_values():
    result = _run_gate(_draft(findings=[_finding(), _finding(category="access_control")]), produced_by="hybrid")
    assert isinstance(result, AnalysisResult)
    assert result.schema_version == "1.0"
    assert result.analyzed_refs == [REF] and result.analysis_meta is META
    for f in result.findings:
        assert f.status == "unverified" and f.severity_if_true is None and f.produced_by == "hybrid"
        assert isinstance(f.finding_id, uuid.UUID)
    evidence = [e for f in result.findings for e in f.evidence] + [e for a in result.advisory_signals for e in a.basis]
    assert evidence and all(e.corroboration == "not_run" and e.anomaly_flags == [] and e.review_required is True
                            for e in evidence)
    assert [f.category for f in result.findings] == ["info_exposure", "access_control"]
    assert len({f.finding_id for f in result.findings}) == 2


def test_clean_draft_is_a_result_with_empty_findings_not_a_rejection():
    """분석 후 깨끗함 = 결과 + findings: [] (폐기와 구분)."""
    result = _run_gate(_draft(findings=[], advisories=[]))
    assert isinstance(result, AnalysisResult) and result.findings == [] and result.advisory_signals == []


def test_server_assigned_field_list_is_pinned():
    assert SERVER_ASSIGNED_FIELDS == {"status", "finding_id", "produced_by", "corroboration", "anomaly_flags",
                                      "review_required", "severity_if_true", "analyzed_refs", "analysis_meta",
                                      "schema_version"}


def test_draft_type_has_no_server_assigned_field_anywhere():
    def names(model) -> set[str]:
        out = set(model.model_fields)
        for field in model.model_fields.values():
            for arg in getattr(field.annotation, "__args__", ()) or ():
                if isinstance(arg, type) and hasattr(arg, "model_fields"):
                    out |= names(arg)
        return out
    assert names(AnalysisDraft) & SERVER_ASSIGNED_FIELDS == set()


# ── 위조 거부: 서버 부여 필드 주입 ─────────────────────────────────────

@pytest.mark.parametrize("value", ["confirmed", "unverified", "false_positive"])
def test_rejects_injected_status(value):
    """status는 값과 무관하게 필드 자체가 초안에 있으면 거부(서버 부여값과 같은 'unverified'도)."""
    _rejected(_run_gate(_draft(findings=[_finding(status=value)])), "server_field_injected")


def _inject(field: str) -> dict:
    d = _draft()
    value = {"status": "confirmed", "finding_id": str(uuid.uuid4()), "produced_by": "rule",
             "corroboration": "matched", "anomaly_flags": [], "review_required": False,
             "severity_if_true": "high", "analyzed_refs": [str(OTHER_REF)], "analysis_meta": {},
             "schema_version": "1.0"}[field]
    target = {"status": "finding", "finding_id": "finding", "produced_by": "finding", "severity_if_true": "finding",
              "corroboration": "evidence", "anomaly_flags": "evidence", "review_required": "evidence",
              "analyzed_refs": "top", "analysis_meta": "top", "schema_version": "top"}[field]
    {"top": d, "finding": d["findings"][0], "evidence": d["findings"][0]["evidence"][0]}[target][field] = value
    return d


@pytest.mark.parametrize("field", sorted(SERVER_ASSIGNED_FIELDS))
def test_rejects_each_server_assigned_field_injected(field):
    _rejected(_run_gate(_inject(field)), "server_field_injected")


@pytest.mark.parametrize("field", ["corroboration", "anomaly_flags", "review_required"])
def test_rejects_server_evidence_field_injected_into_advisory_basis(field):
    d = _draft()
    d["advisory_signals"][0]["basis"][0][field] = {"corroboration": "matched", "anomaly_flags": [],
                                                   "review_required": False}[field]
    _rejected(_run_gate(d), "server_field_injected")


def test_rejects_null_severity_injected_even_though_it_equals_the_server_value():
    _rejected(_run_gate(_draft(findings=[_finding(severity_if_true=None)])), "server_field_injected")


# ── 위조 거부: category 폐쇄형 4종 ───────────────────────────────────

@pytest.mark.parametrize("category", [
    "csrf", "stored_xss", "business_logic", "", "Access_Control", "ACCESS_CONTROL", " access_control",
    "access_control ", "access-control", "accessControl", "info exposure", "ａccess_control", "аccess_control",
    "access_control​"])
def test_rejects_category_outside_closed_four(category):
    _rejected(_run_gate(_draft(findings=[_finding(category=category)])), "category_not_allowed")


# ── 위조 거부: evidence ≥ 1 ─────────────────────────────────────────

def test_rejects_finding_without_evidence():
    _rejected(_run_gate(_draft(findings=[_finding(evidence=[])])), "evidence_missing")


def test_advisory_basis_may_be_empty_documented_limitation():
    """한계 고정: evidence ≥ 1은 Finding에만 적용한다. AdvisorySignal.basis 최소 개수는 (A) 미정."""
    assert isinstance(_run_gate(_draft(advisories=[_advisory(basis=[])])), AnalysisResult)


# ── 위조 거부: transaction_ref ∈ analyzed_refs ───────────────────────

@pytest.mark.parametrize("where", ["finding", "advisory"])
def test_rejects_transaction_ref_outside_analyzed_refs(where):
    d = _draft()
    holder = d["findings"][0]["evidence"] if where == "finding" else d["advisory_signals"][0]["basis"]
    holder.append(_evidence(OTHER_REF))
    _rejected(_run_gate(d), "evidence_ref_outside_analyzed")


@pytest.mark.parametrize("refs", [(), (REF, REF)])
def test_empty_or_duplicate_analyzed_refs_is_a_server_arg_error_before_draft_parsing(refs, monkeypatch):
    parsed: list[int] = []
    real = AnalysisDraft.model_validate_json.__func__
    monkeypatch.setattr(AnalysisDraft, "model_validate_json",
                        classmethod(lambda cls, *a, **k: parsed.append(1) or real(cls, *a, **k)))
    with pytest.raises(ValueError) as exc:
        _run_gate(_draft(), refs=refs)
    assert parsed == [] and str(REF) not in str(exc.value)


def test_nothing_analyzed_cannot_become_a_clean_result():
    """빈 analyzed_refs + findings 없는 초안 → '분석 안 함 ≠ 분석 후 깨끗함'((A) §2.5) — AnalysisResult가 생기지 않는다."""
    with pytest.raises(ValueError):
        _run_gate(_draft(findings=[], advisories=[]), refs=())


# ── 위조 거부: 형 변환 우회(W1-05 `masked: 1` 교훈) ────────────────────

def _at(path: str, value) -> dict:
    d = _draft()
    *parents, last = path.split(".")
    node = d
    for p in parents:
        node = node[int(p)] if p.isdigit() else node[p]
    node[int(last) if last.isdigit() else last] = value
    return d


@pytest.mark.parametrize("path,value,code", [
    ("findings.0.category", 1, "category_not_allowed"),
    ("findings.0.category", True, "category_not_allowed"),
    ("findings.0.category", None, "category_not_allowed"),
    ("findings.0.category", ["access_control"], "category_not_allowed"),
    ("findings.0.claim_basis", 1, "draft_schema_invalid"),
    ("findings.0.claim_basis", "1", "draft_schema_invalid"),
    ("findings.0.claim_basis", True, "draft_schema_invalid"),
    ("findings.0.evidence.0.locus", 0, "draft_schema_invalid"),
    ("findings.0.evidence.0.locus", True, "draft_schema_invalid"),
    ("findings.0.evidence.0.transaction_ref", 1, "draft_schema_invalid"),
    ("findings.0.evidence.0.pointer", 1, "draft_schema_invalid"),
    ("findings.0.hypothesis", 1, "draft_schema_invalid"),
    ("findings.0.next_steps.0.type", True, "draft_schema_invalid"),
    ("findings.0.next_steps.0.type", "Verification", "draft_schema_invalid"),
    ("findings.0.evidence", {"0": {}}, "draft_schema_invalid"),
    ("findings.0.limitations", "본문 일부만 분석됨", "draft_schema_invalid"),
    ("advisory_signals.0.type", 1, "draft_schema_invalid"),
    ("advisory_signals.0.type", "finding", "draft_schema_invalid"),
])
def test_rejects_type_coercion_bypass(path, value, code):
    _rejected(_run_gate(_at(path, value)), code)


# ── 위조 거부: 부분 위반 → 전체 폐기(부분 수용 0) ──────────────────────

PARTIAL = {
    "status_injected": (lambda d: d["findings"][1].update(status="confirmed"), "server_field_injected"),
    "bad_category": (lambda d: d["findings"][1].update(category="csrf"), "category_not_allowed"),
    "no_evidence": (lambda d: d["findings"][1].update(evidence=[]), "evidence_missing"),
    "ref_outside_finding": (lambda d: d["findings"][1]["evidence"].append(_evidence(OTHER_REF)),
                            "evidence_ref_outside_analyzed"),
    "ref_outside_advisory": (lambda d: d["advisory_signals"][1]["basis"].append(_evidence(OTHER_REF)),
                             "evidence_ref_outside_analyzed"),
}


@pytest.mark.parametrize("kind", sorted(PARTIAL))
def test_partial_violation_rejects_whole_result(kind):
    d = _draft(findings=[_finding(), _finding(), _finding(category="security_misconfig")],
               advisories=[_advisory(), _advisory()])
    assert isinstance(_run_gate(copy.deepcopy(d)), AnalysisResult)  # 대조: 위반 전에는 통과
    mutate, code = PARTIAL[kind]
    mutate(d)
    _rejected(_run_gate(d), code)


# ── 폐기는 명시적이다(예외·빈 결과로 숨기지 않음) ──────────────────────

@pytest.mark.parametrize("raw,code", [
    (b"", "draft_unparseable"), (b"not json", "draft_unparseable"), (b"[]", "draft_unparseable"),
    (b"null", "draft_unparseable"), (b'"findings"', "draft_unparseable"), (b"\xff\xfe", "draft_unparseable"),
    (b'{"findings": []}', "draft_schema_invalid"), (b'{"advisory_signals": []}', "draft_schema_invalid"),
    (b'{"findings": [], "advisory_signals": [], "notes": "x"}', "unknown_field"),
])
def test_unusable_draft_is_an_explicit_rejection_not_an_exception_or_empty_result(raw, code):
    _rejected(_run_gate(raw), code)


def test_reason_codes_are_a_closed_list():
    with pytest.raises(ValueError):
        OutputRejection(("something_else",))
    with pytest.raises(ValueError):
        OutputRejection(())
    assert len(set(REASON_CODES)) == len(REASON_CODES)


# ── 서버 인자 검사: 초안 파싱 전, 값 미반사 ────────────────────────────

@pytest.mark.parametrize("kwargs", [
    {"produced_by": "llm_v2"}, {"produced_by": "LLM"}, {"produced_by": 1},
    {"analyzed_refs": [str(REF)]}, {"analyzed_refs": str(REF)}, {"analysis_meta": {}},
])
def test_bad_server_args_raise_before_draft_parsing_without_values(kwargs, monkeypatch):
    parsed: list[int] = []
    real = AnalysisDraft.model_validate_json.__func__
    monkeypatch.setattr(AnalysisDraft, "model_validate_json",
                        classmethod(lambda cls, *a, **k: parsed.append(1) or real(cls, *a, **k)))
    args = {"analyzed_refs": [REF], "produced_by": "llm", "analysis_meta": META} | kwargs
    marker = secrets.token_hex(8)
    with pytest.raises(ValueError) as exc:
        gate.validate_draft(json.dumps(_draft(findings=[_finding(hypothesis=marker)])), **args)
    assert parsed == []
    message = str(exc.value)
    assert marker not in message and str(REF) not in message and "llm_v2" not in message


# ── 저장용 타입: 지금 부여할 수 있는 값만 ───────────────────────────────

def _stored_finding(**over) -> dict:
    result = _run_gate(_draft())
    assert isinstance(result, AnalysisResult)
    return result.findings[0].model_dump() | over


@pytest.mark.parametrize("over", [{"severity_if_true": "high"}, {"severity_if_true": 0}])
def test_stored_finding_allows_only_null_severity(over):
    Finding.model_validate(_stored_finding())  # 대조: 서버가 만든 값은 통과
    with pytest.raises(ValidationError):
        Finding.model_validate(_stored_finding(**over))


def test_stored_finding_requires_severity_field_present():
    data = _stored_finding()
    del data["severity_if_true"]
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_stored_evidence_allows_only_empty_anomaly_flags():
    data = _stored_finding()
    data["evidence"][0]["anomaly_flags"] = ["hallucinated_literal_suspected"]
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


# ── 감사 위생: 사유 코드만, 초안 원문 0 ───────────────────────────────

@pytest.fixture
def store(tmp_path):
    path = tmp_path / "audit.sqlite3"
    handler = attach_audit_store(path)
    yield path
    detach_audit_store(handler)


def test_rejection_audit_has_reason_codes_only_no_draft_content(store, caplog):
    markers = [secrets.token_hex(10) for _ in range(5)]
    d = _draft(findings=[_finding(hypothesis=markers[0], category=markers[1])])
    d["findings"][0]["evidence"][0]["observation"] = markers[2]
    d["findings"][0]["x_" + markers[3]] = markers[4]
    d["advisory_signals"][0]["basis"].append(_evidence(OTHER_REF))
    with caplog.at_level(logging.DEBUG):
        result = _run_gate(d)
        ref_only = _draft(findings=[_finding(evidence=[_evidence(OTHER_REF) | {"pointer": markers[0]}])])
        _run_gate(ref_only)
    assert isinstance(result, OutputRejection)
    events = read_audit_events(store)
    assert [e["event"] for e in events] == ["output_rejected", "output_rejected"]
    assert all(set(e["message"].split("reasons=", 1)[1].split(",")) <= set(REASON_CODES) for e in events)
    db_bytes = b"".join(p.read_bytes() for p in store.parent.iterdir() if p.name.startswith(store.name))
    for m in markers + [str(OTHER_REF)]:
        assert m.encode() not in db_bytes
        assert m not in caplog.text
        assert m not in repr(result)


# ── 위치: 파이프라인 패키지(토큰 실패 시 미호출 스파이 대상) ──────────────

def test_gate_is_in_pipeline_package_so_auth_spies_cover_it():
    assert "sentinel.pipeline.output_gate.validate_draft" in {f"{m.__name__}.{n}" for m, n in PIPELINE_FUNCTIONS}


# ── 변이 확인: 각 검사가 하중을 지지한다(변이본 로드를 먼저 증명) ──────────────

STAMP = "output_gate_probe"
_DRIVER = """
import sys, pytest
import sentinel.output_schema, sentinel.pipeline.output_gate  # pytest의 pythonpath 삽입 전에 변이본을 먼저 적재
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_output_gate.py::"
MUTATIONS = {
    # 검사 ① 초안 스키마: 추가 필드 금지 해제 → 서버 부여 필드 주입이 통과
    "draft_schema_open": ("src/sentinel/output_schema.py", "sentinel.output_schema",
                          'class _Draft(BaseModel):\n    model_config = ConfigDict(strict=True, extra="forbid"',
                          'class _Draft(BaseModel):\n    model_config = ConfigDict(strict=True, extra="ignore"',
                          [_T + "test_rejects_each_server_assigned_field_injected"]),
    # 검사 ② category 폐쇄형: 초안 Literal 해제(저장 타입이 2차로 막지만 사유가 달라짐)
    "category_open": ("src/sentinel/output_schema.py", "sentinel.output_schema",
                      "    category: Category\n    hypothesis: str\n    evidence: Annotated[list[EvidenceDraft]",
                      "    category: str\n    hypothesis: str\n    evidence: Annotated[list[EvidenceDraft]",
                      [_T + "test_rejects_category_outside_closed_four"]),
    # 검사 ③ evidence ≥ 1: 초안 최소 개수 해제
    "evidence_min_off": ("src/sentinel/output_schema.py", "sentinel.output_schema",
                         "evidence: Annotated[list[EvidenceDraft], Field(min_length=1)]",
                         "evidence: list[EvidenceDraft]",
                         [_T + "test_rejects_finding_without_evidence"]),
    # 검사 ④ 참조 무결성 해제
    "ref_check_off": ("src/sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate",
                      "    if outside:\n", "    if False:\n",
                      [_T + "test_rejects_transaction_ref_outside_analyzed_refs"]),
    # 부분 수용 금지 해제: 위반 항목만 빼고 나머지를 결과로 반환
    "partial_accept": ("src/sentinel/pipeline/output_gate.py", "sentinel.pipeline.output_gate",
                       '    if outside:\n        return _reject(("evidence_ref_outside_analyzed",))\n',
                       "    if outside:\n        parsed = parsed.model_copy(update={k: [x for i, x in "
                       "enumerate(getattr(parsed, k)) if (k, i) not in outside] for k in "
                       "('findings', 'advisory_signals')})\n",
                       [_T + "test_partial_violation_rejects_whole_result[ref_outside_finding]",
                        _T + "test_partial_violation_rejects_whole_result[ref_outside_advisory]"]),
}


def _run_mutant(src_dir: Path, module: str, nodes: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(src_dir), str(REPO_ROOT)]), "PYTHONUTF8": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                          cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_gate_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    """원본은 위조를 거부하고(이 스위트의 해당 테스트), 그 검사를 끈 변이본에서는 그 적대 테스트가 실패한다
    — 단, 변이본이 실제로 로드됐음을 먼저 증명한다."""
    rel, module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], tmp_path / "mut" / "src",
                                rel.removeprefix("src/"), old, new)
    r = _run_mutant(tmp_path / "mut" / "src", module, nodes)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음 — 이 검사가 하중을 지지하지 않음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"


def test_mutant_shadowed_by_original_module_is_detected(tmp_path):
    """W1-08 함정 재현: 변이본을 만들었지만 실행이 원본 모듈을 쓰면 장치가 '다른 사본'으로 잡는다."""
    rel, module, old, new, nodes = MUTATIONS["ref_check_off"]
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], tmp_path / "mut" / "src",
                                rel.removeprefix("src/"), old, new)
    r = _run_mutant(REPO_ROOT / "src", module, nodes)  # 변이본 대신 원본 src를 적재
    out = r.stdout + r.stderr
    assert f"{STAMP} module=" in out  # 표지는 있다(표지 부재로 인한 거짓 통과가 아님)
    assert r.returncode == 0, out  # 원본은 위조를 거부 → 해당 적대 테스트 통과
    with pytest.raises(MutationNotApplied, match="다른 사본"):
        assert_loaded_from(out, STAMP, mutant)
