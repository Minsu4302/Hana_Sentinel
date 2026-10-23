"""파이프라인 ④ ExecutionResponse — (A) §2.5. "분석 안 함 ≠ 분석 후 깨끗함."

정상 입력(①②③ 통과)은 findings가 아니라 analysis_status="not_implemented" + manifest_snapshot을 받는다.
스냅샷은 실제 manifest(guardrails.yaml SSOT 재파생)와 일치해야 하며, manifest가 없거나 깨졌으면 기동 거부.
"""
from __future__ import annotations

import json
import shutil

import pytest
import uvicorn
from pydantic import ValidationError

import sentinel.server.serve as serve_mod
from sentinel.manifest_snapshot import MANIFEST_ENV, ManifestError, load_manifest_snapshot
from sentinel.pipeline.execution import SKIPPED_REASONS
from sentinel.schema import ExecutionResponse
from sentinel.server.app import create_app
from sentinel.server.auth import TOKEN_ENV
from sentinel.server.config import ServerConfig
from tools.guardrails import MANIFEST_PATH, REPO_ROOT
from tools.guardrails.manifest import derive_manifest
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_schema import _env, _raw


def _json(sent) -> dict:
    return json.loads(b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


def _compact(manifest: dict) -> dict:
    return {"schema_version": manifest["schema_version"], "spec": manifest["spec"],
            "capabilities": {k: {"status": v["status"], "effective_status": v["effective_status"]}
                             for k, v in manifest["capabilities"].items()}}


def test_valid_request_gets_not_implemented_execution_response_not_empty_findings(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    body = _json(sent)
    assert _status(sent) == 200
    assert set(body) == {"analysis_status", "skipped_reasons", "manifest_snapshot"}
    assert body["analysis_status"] == "not_implemented"
    assert "findings" not in body  # 빈 findings가 아니라 '분석 안 함'
    assert body["skipped_reasons"] == list(SKIPPED_REASONS)


def test_manifest_snapshot_matches_the_real_manifest_and_its_ssot_derivation(token, spec, entries):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    snapshot = _json(sent)["manifest_snapshot"]
    assert snapshot == _compact(json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))
    assert snapshot == _compact(derive_manifest(entries, spec, REPO_ROOT))  # guardrails.yaml 재파생과 일치


def test_snapshot_does_not_claim_unproven_protection(token, entries):
    """스냅샷의 enforced = 레지스트리에서 검증 테스트가 붙은 enforced뿐(없는 보호를 있는 척 안 함)."""
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    caps = _json(sent)["manifest_snapshot"]["capabilities"]
    proven = {e["id"] for e in entries if e["week1_status"]["state"] == "enforced" and e["verification_tests"]}
    assert {k for k, v in caps.items() if v["status"] == "enforced"} == proven
    assert caps["audit_write_failure"]["status"] == "not_implemented"
    assert caps["output_schema_gate"] == {"status": "derived", "effective_status": "not_implemented"}


def test_tampered_manifest_file_would_diverge_from_ssot(tmp_path, spec, entries):
    """손 편집된 manifest는 SSOT 재파생과 불일치 → 위 일치 테스트·guardrails check가 실패하는 경로."""
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    data["capabilities"]["receipt_hmac"].update(status="enforced", effective_status="enforced")
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(data), encoding="utf-8")
    assert load_manifest_snapshot(forged) != _compact(derive_manifest(entries, spec, REPO_ROOT))


@pytest.mark.parametrize("content", [None, "", "not json", "[]", '{"spec": "x"}',
                                     '{"spec": "x", "capabilities": {}}',
                                     '{"spec": "x", "capabilities": {"k": {"status": "mostly"}}}',
                                     '{"spec": "x", "capabilities": {"k": {"status": "derived", '
                                     '"effective_status": "derived"}}}'])
def test_missing_or_broken_manifest_refuses_startup(tmp_path, monkeypatch, token, content):
    path = tmp_path / "manifest.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    monkeypatch.setenv(MANIFEST_ENV, str(path))
    monkeypatch.setenv(TOKEN_ENV, token.decode())
    ran = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, *a, **k: ran.append(self))
    with pytest.raises(ManifestError):
        serve_mod.serve(ServerConfig(port=0))
    assert ran == []
    with pytest.raises(ManifestError):
        create_app(token)


def test_alternate_manifest_path_is_honored(tmp_path, monkeypatch, token):
    path = tmp_path / "copy.json"
    shutil.copy(MANIFEST_PATH, path)
    monkeypatch.setenv(MANIFEST_ENV, str(path))
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    assert _json(sent)["manifest_snapshot"] == load_manifest_snapshot(MANIFEST_PATH)


@pytest.mark.parametrize("bad", [
    {"analysis_status": "done", "skipped_reasons": ["x"], "manifest_snapshot": {}},
    {"analysis_status": "not_implemented", "skipped_reasons": [], "manifest_snapshot": {}},
    {"analysis_status": "not_implemented", "skipped_reasons": ["x"], "manifest_snapshot": {}, "findings": []},
])
def test_execution_response_type_cannot_claim_analysis_or_carry_findings(bad):
    with pytest.raises(ValidationError):
        ExecutionResponse.model_validate(bad)


def test_response_snapshot_is_a_copy_not_shared_state(token):
    snapshot = load_manifest_snapshot()
    app = create_app(token, snapshot)
    body = _json(_drive(app, _scope([(HEADER, token)]), _raw(_env()))[0])
    body["manifest_snapshot"]["capabilities"]["receipt_hmac"]["status"] = "enforced"
    again = _json(_drive(app, _scope([(HEADER, token)]), _raw(_env()))[0])
    assert again["manifest_snapshot"]["capabilities"]["receipt_hmac"]["status"] == "not_implemented"
