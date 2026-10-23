"""`manifest_derivation` — (A) §3 → guardrails.yaml → manifest 파생 사슬.

정상 일치만이 아니라 '위조 거부'로 증명한다: 거짓 enforced, not_implemented의 enforced 참칭,
중복 ID, 미지 status, 스키마 밖 구조, 손 편집된 생성물 → 전부 거부.
"""
from __future__ import annotations

import copy
import json
import shutil

import pytest

import tools.guardrails.__main__ as cli
from tools.guardrails import MANIFEST_PATH, REGISTRY_PATH, REPO_ROOT, SPEC_PATH
from tools.guardrails.manifest import derive_manifest, effective_state, render_manifest
from tools.guardrails.registry import FIELDS, RegistryError, render_yaml, sync, validate
from tools.guardrails.spec import SpecError, parse_spec

# 위조에 쓸 '실재하는' 검증 테스트 — 테스트가 실재해도 (A)를 넘는 주장은 거부돼야 한다.
REAL_TEST = "tests/test_guardrails.py::test_committed_manifest_matches_rederivation"


def _get(entries: list[dict], key: str) -> dict:
    return next(e for e in entries if e["id"] == key)


def _rejected(entries, spec, *needles: str) -> str:
    with pytest.raises(RegistryError) as exc:
        validate(entries, spec, REPO_ROOT)
    msg = str(exc.value)
    for n in needles:
        assert n in msg
    return msg


# ── 정상: 정본 일치 ──────────────────────────────────────────────

def test_every_guardrail_has_exactly_the_six_fields(entries):
    assert entries
    for e in entries:
        assert tuple(e) == FIELDS, e.get("id")


def test_registry_is_rederived_from_design_decision_section3(spec, entries):
    """뷰 동기화 ①: guardrails.yaml == (A) §3 재파생(enforced 승격만 보존)."""
    assert REGISTRY_PATH.read_text(encoding="utf-8") == render_yaml(sync(spec, entries), spec)
    assert [e["id"] for e in entries] == [r.key for r in spec.rows]


def test_committed_manifest_matches_rederivation(spec, entries):
    """뷰 동기화 ③: 커밋된 manifest 생성물 == guardrails.yaml 재파생."""
    expected = render_manifest(derive_manifest(entries, spec, REPO_ROOT))
    assert MANIFEST_PATH.read_text(encoding="utf-8") == expected


def test_output_schema_gate_is_a_derived_rollup_not_an_enforced_claim(spec, entries):
    gate = _get(entries, "output_schema_gate")
    assert gate["week1_status"]["state"] == "derived"
    assert gate["week1_status"]["derived_from"] == [
        "evidence_min_one", "evidence_ref_integrity", "server_assigned_status", "category_closed_enum"]
    assert gate["verification_tests"] == []
    cap = derive_manifest(entries, spec, REPO_ROOT)["capabilities"]["output_schema_gate"]
    assert cap["effective_status"] != "enforced"


def test_derived_rollup_is_enforced_only_when_every_child_is_enforced():
    def entry(key, state, children=None):
        status = {"state": state}
        if children:
            status["derived_from"] = children
        return {"id": key, "week1_status": status}

    kids = {k: entry(k, "enforced") for k in ("a", "b")}
    gate = entry("gate", "derived", ["a", "b"])
    assert effective_state(gate, {**kids, "gate": gate}) == "enforced"
    kids["b"] = entry("b", "not_implemented")
    assert effective_state(gate, {**kids, "gate": gate}) == "not_implemented"


def test_enforced_keys_point_only_to_real_tests(entries):
    for e in entries:
        if e["week1_status"]["state"] == "enforced":
            assert e["verification_tests"], e["id"]


# ── 위조 거부: 거짓 enforced / 참칭 ─────────────────────────────────

def test_rejects_enforced_without_verification_tests(spec, entries):
    e = _get(entries, "egress_static_check")  # (A) 목표=enforced, 실제 테스트 없음
    e["week1_status"] = {"state": "enforced"}
    _rejected(entries, spec, "egress_static_check", "검증 테스트 식별자 없음")


def test_rejects_enforced_pointing_to_nonexistent_test(spec, entries):
    e = _get(entries, "egress_static_check")
    e["week1_status"] = {"state": "enforced"}
    e["verification_tests"] = ["tests/test_egress.py::test_does_not_exist"]
    _rejected(entries, spec, "egress_static_check", "실재하지 않음")


def test_rejects_enforced_pointing_to_non_test_function(spec, entries):
    e = _get(entries, "egress_static_check")
    e["week1_status"] = {"state": "enforced"}
    e["verification_tests"] = ["tests/test_guardrails.py::_get"]
    _rejected(entries, spec, "egress_static_check", "실재하지 않음")


@pytest.mark.parametrize("key", ["token_hardening", "receipt_hmac", "no_multiagent_rag", "eval_harness"])
def test_rejects_not_implemented_key_claimed_as_enforced(spec, entries, key):
    """테스트가 실재해도 (A)가 not_implemented(→N주차)로 둔 키는 enforced가 될 수 없다."""
    e = _get(entries, key)
    e["week1_status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(entries, spec, key, "참칭")


@pytest.mark.parametrize("key", ["egress_enforcement_owner", "branch_protection"])
def test_rejects_unverifiable_key_claimed_as_enforced(spec, entries, key):
    e = _get(entries, key)
    e["week1_status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(entries, spec, key, "참칭")


def test_rejects_derived_rollup_claimed_as_enforced(spec, entries):
    e = _get(entries, "output_schema_gate")
    e["week1_status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(entries, spec, "output_schema_gate", "참칭")


def test_rejects_target_week_drift(spec, entries):
    """목표 주차를 앞당겨 적는 것도 (A)와 다르면 거부."""
    _get(entries, "token_hardening")["week1_status"]["target"] = "1주차"
    _rejected(entries, spec, "token_hardening", "(A) 파생값")


# ── 위조 거부: 구조 ─────────────────────────────────────────────

def test_rejects_duplicate_id(spec, entries):
    entries.append(copy.deepcopy(entries[0]))
    _rejected(entries, spec, "중복 가드레일 ID", entries[0]["id"])


def test_rejects_unknown_status(spec, entries):
    _get(entries, "receipt_hmac")["week1_status"] = {"state": "mostly_enforced"}
    _rejected(entries, spec, "미지 status", "mostly_enforced")


@pytest.mark.parametrize("field", FIELDS)
def test_rejects_missing_field(spec, entries, field):
    del entries[0][field]
    _rejected(entries, spec, "필수 필드 누락", field)


def test_rejects_field_outside_schema(spec, entries):
    entries[0]["confidence"] = "high"
    _rejected(entries, spec, "스키마 밖 필드", "confidence")


def test_rejects_manifest_key_differing_from_id(spec, entries):
    entries[0]["manifest_key"] = "something_else"
    _rejected(entries, spec, "manifest_key")


def test_rejects_tests_attached_to_non_enforced_key(spec, entries):
    _get(entries, "receipt_hmac")["verification_tests"] = [REAL_TEST]
    _rejected(entries, spec, "receipt_hmac", "enforced만 허용")


def test_rejects_key_not_in_design_decision(spec, entries):
    extra = copy.deepcopy(_get(entries, "receipt_hmac"))
    extra["id"] = extra["manifest_key"] = "invented_guardrail"
    entries.append(extra)
    _rejected(entries, spec, "invented_guardrail", "(A) §3에 없는 키")


def test_rejects_registry_missing_a_design_decision_key(spec, entries):
    entries.remove(_get(entries, "audit_write_failure"))
    _rejected(entries, spec, "audit_write_failure", "guardrails.yaml에 없음")


def test_rejects_description_or_layer_drift_from_design_decision(spec, entries):
    _get(entries, "loopback_binding")["description"] = "0.0.0.0 바인딩"
    _get(entries, "secret_scan_hook")["target_layer"] = "테스트"
    _rejected(entries, spec, "loopback_binding", "description", "secret_scan_hook", "target_layer")


def test_rejects_derived_rollup_with_unknown_child(spec, entries):
    _get(entries, "output_schema_gate")["week1_status"]["derived_from"].append("ghost_key")
    _rejected(entries, spec, "ghost_key")


# ── 위조 거부: (A) 정본 파서는 추측하지 않는다 ───────────────────────

def test_spec_parser_rejects_unmapped_target_layer():
    text = SPEC_PATH.read_text(encoding="utf-8")
    bad = text.replace("| 아키텍처 테스트 | enforced | `no_autonomous_send` |",
                       "| 런타임 감시 | enforced | `no_autonomous_send` |")
    assert bad != text
    with pytest.raises(SpecError, match="매핑되지 않은 목표층위"):
        parse_spec(bad)


def test_spec_parser_rejects_unparseable_status():
    text = SPEC_PATH.read_text(encoding="utf-8")
    bad = text.replace("| not_implemented → 2주차 | `receipt_hmac` |", "| 거의 됨 | `receipt_hmac` |")
    assert bad != text
    with pytest.raises(SpecError, match="해석할 수 없는 1주차 상태"):
        parse_spec(bad)


# ── 위조 거부: 생성기·검사기(fail-closed) ───────────────────────────

@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """CLI가 실제 레포 파일 대신 임시 사본을 읽고 쓰게 한다."""
    reg, man = tmp_path / "guardrails.yaml", tmp_path / "capability_manifest.json"
    shutil.copy(REGISTRY_PATH, reg)
    shutil.copy(MANIFEST_PATH, man)
    monkeypatch.setattr(cli, "REGISTRY_PATH", reg)
    monkeypatch.setattr(cli, "MANIFEST_PATH", man)
    return reg, man


def test_manifest_generation_is_refused_for_false_enforced_claim(sandbox):
    reg, man = sandbox
    man.unlink()
    text = reg.read_text(encoding="utf-8")
    forged = text.replace(
        "    week1_status:\n      state: not_implemented\n      target: \"1주차\"\n"
        "    verification_tests: []\n    manifest_key: egress_static_check",
        "    week1_status:\n      state: enforced\n"
        "    verification_tests: []\n    manifest_key: egress_static_check")
    assert forged != text
    reg.write_text(forged, encoding="utf-8")
    assert cli.main(["manifest"]) == 1
    assert not man.exists()  # 생성 거부 — 부분 산출물도 남기지 않음


def test_check_rejects_hand_edited_manifest(sandbox):
    _, man = sandbox
    data = json.loads(man.read_text(encoding="utf-8"))
    data["capabilities"]["receipt_hmac"]["status"] = "enforced"
    data["capabilities"]["receipt_hmac"]["effective_status"] = "enforced"
    man.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    assert cli.main(["check"]) == 1


def test_check_rejects_registry_out_of_sync_with_design_decision(sandbox):
    reg, _ = sandbox
    text = reg.read_text(encoding="utf-8")
    reg.write_text(text.replace("# enforced는 실제 통과 테스트가 있는 것만", "# 손으로 고침"), encoding="utf-8")
    assert cli.main(["check"]) == 1


def test_check_passes_on_untouched_copies(sandbox):
    assert cli.main(["check"]) == 0
