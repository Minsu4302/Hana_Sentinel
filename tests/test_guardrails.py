"""`manifest_derivation`·`manifest_honesty` — 실제 레지스트리: (A) §3 → guardrails.yaml → manifest 파생 사슬.

실제 레지스트리 자체의 정합(재파생 일치, 실제 파생 롤업, 구조 위조 거부)을 본다. 상태를 예시로 쓰는 위조 거부(거짓 enforced,
not_implemented·unverifiable·derived의 enforced 참칭, 미지 status, 파서의 상태·층위 표기)는 실제 상태가 정상 진척으로 바뀌므로
합성 레지스트리로 한다 — `tests/test_guardrails_synthetic.py`.
"""
from __future__ import annotations

import copy
import json
import shutil

import pytest

import tools.guardrails.__main__ as cli
from tools.guardrails import MANIFEST_PATH, REGISTRY_PATH, REPO_ROOT
from tools.guardrails.manifest import derive_manifest, effective_state, render_manifest
from tools.guardrails.registry import FIELDS, RegistryError, load_registry, render_yaml, sync, validate

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
    assert gate["status"]["state"] == "derived"
    assert gate["status"]["derived_from"] == [
        "evidence_min_one", "evidence_ref_integrity", "server_assigned_status", "category_closed_enum"]
    assert gate["verification_tests"] == []
    cap = derive_manifest(entries, spec, REPO_ROOT)["capabilities"]["output_schema_gate"]
    children = {e["id"]: e["status"]["state"] for e in entries if e["id"] in gate["status"]["derived_from"]}
    assert cap["status"] == "derived"  # 자체 enforced 주장이 아니다 — 실효 상태는 하위 4키의 AND
    assert cap["effective_status"] == ("enforced" if set(children.values()) == {"enforced"} else "not_implemented")


def test_derived_rollup_is_enforced_only_when_every_child_is_enforced():
    def entry(key, state, children=None):
        status = {"state": state}
        if children:
            status["derived_from"] = children
        return {"id": key, "status": status}

    kids = {k: entry(k, "enforced") for k in ("a", "b")}
    gate = entry("gate", "derived", ["a", "b"])
    assert effective_state(gate, {**kids, "gate": gate}) == "enforced"
    kids["b"] = entry("b", "not_implemented")
    assert effective_state(gate, {**kids, "gate": gate}) == "not_implemented"


@pytest.mark.parametrize("forged_state", ["not_implemented", "disabled", "unverifiable"])
@pytest.mark.parametrize("child", ["evidence_min_one", "evidence_ref_integrity", "server_assigned_status",
                                   "category_closed_enum"])
def test_real_output_schema_gate_is_not_enforced_when_any_child_is_forged_down(entries, child, forged_state):
    """실제 레지스트리에서 하위 키 하나만 낮춰도 파생값이 enforced가 되지 않는다(OR로 잘못 동작하면 잡힘)."""
    by_id = {e["id"]: e for e in entries}
    gate = by_id["output_schema_gate"]
    assert child in gate["status"]["derived_from"]
    by_id[child]["status"] = {"state": forged_state, "target": "위조"}
    assert effective_state(gate, by_id) == "not_implemented"


def test_targetless_derived_is_accepted_with_no_target(spec):
    gate = spec.by_key()["output_schema_gate"]
    assert gate.state == "derived" and gate.target is None and len(gate.derived_from) == 4
    cap = derive_manifest(load_registry(REGISTRY_PATH), spec, REPO_ROOT)["capabilities"]["output_schema_gate"]
    assert "target" not in cap


def test_enforced_keys_point_only_to_real_tests(entries):
    for e in entries:
        if e["status"]["state"] == "enforced":
            assert e["verification_tests"], e["id"]


# ── 위조 거부: 거짓 enforced / 참칭 ─────────────────────────────────


# ── 위조 거부: 구조 ─────────────────────────────────────────────

def test_rejects_duplicate_id(spec, entries):
    entries.append(copy.deepcopy(entries[0]))
    _rejected(entries, spec, "중복 가드레일 ID", entries[0]["id"])


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


def test_rejects_registry_missing_a_design_decision_key(spec, entries):
    entries.remove(_get(entries, "audit_write_failure"))
    _rejected(entries, spec, "audit_write_failure", "guardrails.yaml에 없음")


def test_rejects_description_or_layer_drift_from_design_decision(spec, entries):
    _get(entries, "loopback_binding")["description"] = "0.0.0.0 바인딩"
    _get(entries, "secret_scan_hook")["target_layer"] = "테스트"
    _rejected(entries, spec, "loopback_binding", "description", "secret_scan_hook", "target_layer")


# ── 위조 거부: (A) 정본 파서는 추측하지 않는다 ───────────────────────


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


def test_check_rejects_registry_out_of_sync_with_design_decision(sandbox):
    reg, _ = sandbox
    text = reg.read_text(encoding="utf-8")
    reg.write_text(text.replace("# enforced는 실제 통과 테스트가 있는 것만", "# 손으로 고침"), encoding="utf-8")
    assert cli.main(["check"]) == 1


def test_check_passes_on_untouched_copies(sandbox):
    assert cli.main(["check"]) == 0
