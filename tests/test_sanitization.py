"""파이프라인 ③ Sanitization 독립 재검증 — `sanitization_trust`.

(A) §2.3 신뢰 경계·§3.6을 '위조 거부'로 증명한다: 영수증이 `applied:true, failed:false`라고 주장해도
데이터에 생문자열이 남아 있으면 거부(영수증 무시, 데이터를 믿음). 화이트리스트 밖 자리의 생문자열도 값
재스캔(주 방어선)이 잡는다. 가짜 비밀값은 전부 런타임 조립(N5·N7) — 이 파일에 실제 형태의 리터럴 없음.
"""
from __future__ import annotations

import base64
import copy
import json
import logging
import secrets
from urllib.parse import quote

import pytest

from sentinel.pipeline import sanitization_check, schema_gate
from sentinel.pipeline.sanitization_check import (
    PATTERNS, REQ_BODY_CAP, RESP_BODY_CAP, SanitizationRejected, verify_sanitization)
from sentinel.pipeline.schema_gate import parse_envelope
from sentinel.sanitization_policy import DEFAULT_POLICY, SanitizationPolicy
from sentinel.server.app import MAX_REQUEST_BYTES, create_app
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_schema import _DEL, T0, _env, _raw, _set

# 패턴 이름 → 런타임 조립한 가짜 생문자열
FAKES = {
    "jwt": "eyJ" + "h" * 12 + "." + "eyJ" + "p" * 12 + "." + "s" * 16,
    "auth_scheme_credential": "Bearer " + "t0k3n" * 5,
    "aws_access_key_id": "AKIA" + "Z" * 16,
    "github_token": "ghp" + "_" + "a1B2" * 9,
    "slack_token": "xoxb" + "-" + "1234567890-abcdef",
    "api_secret_key": "sk-" + "ant-" + "Q" * 40,
    "private_key_block": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "session_cookie_pair": "JSESSIONID" + "=" + "d" * 24,
    "credential_json_field": '{"pass' + 'word": "' + "hunter2" + '"}',
    "credential_form_field": "user=alice&pass" + "word=" + "hunter2",
}


def _lying_receipt(env: dict) -> dict:
    """영수증은 '마스킹 완료'라고 주장 — 재검증은 이 주장을 믿지 않아야 한다."""
    s = env["transactions"][0]["meta"]["sanitization"]
    s.update(applied=True, failed=False, redacted_count=3)
    return env


def _plant(location: str, value: str) -> dict:
    env = _lying_receipt(_env())
    tx = env["transactions"][0]
    if location == "unlisted_request_header":
        tx["request"]["headers"].append({"name": "X-Debug-Context", "value": value})
    elif location == "unlisted_response_header":
        tx["response"]["headers"].append({"name": "X-Echo", "value": value})
    elif location == "query_param_value":
        tx["request"]["query_params"][0]["value"] = value
    elif location == "query_param_name":
        tx["request"]["query_params"][0]["name"] = value
    elif location == "percent_encoded_param":
        tx["request"]["query_params"][0]["value"] = quote(value)
    elif location == "request_path":
        tx["request"]["path"] = "/rest/user/" + value
    elif location == "request_body":
        tx["request"]["body"].update(content=value, size_bytes=len(value))
    elif location == "response_body":
        tx["response"]["body"].update(content=value, size_bytes=len(value))
    elif location == "base64_request_body":
        tx["request"]["body"].update(content=base64.b64encode(value.encode()).decode(), encoding="base64")
    elif location == "origin_ref":
        tx["meta"]["origin_ref"] = value
    else:
        raise AssertionError(location)
    return env


LOCATIONS = ["unlisted_request_header", "unlisted_response_header", "query_param_value", "query_param_name",
             "percent_encoded_param", "request_path", "request_body", "response_body", "base64_request_body",
             "origin_ref"]


def _reasons(env: dict, policy: SanitizationPolicy = DEFAULT_POLICY) -> tuple[str, ...]:
    with pytest.raises(SanitizationRejected) as exc:
        verify_sanitization(parse_envelope(_raw(env)), policy)
    return exc.value.reasons


# ── 정상(대조군): 실제로 마스킹된 입력은 통과 ─────────────────────────────

def test_actually_masked_input_passes():
    verify_sanitization(parse_envelope(_raw(_lying_receipt(_env()))))


def test_actually_masked_input_reaches_not_implemented_path(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    assert _status(sent) == 200


def test_every_policy_pattern_has_an_adversarial_sample():
    assert set(FAKES) == set(PATTERNS)


# ── 위조 거부: applied:true인데 생문자열 잔존 → 거부(영수증 무시) ────────────────

@pytest.mark.parametrize("location", LOCATIONS)
@pytest.mark.parametrize("pattern", sorted(FAKES))
def test_raw_secret_is_rejected_despite_applied_true_receipt(pattern, location):
    reasons = _reasons(_plant(location, FAKES[pattern]))
    assert any(r.startswith(f"{pattern}@") for r in reasons), reasons


def test_http_lying_receipt_with_raw_token_is_rejected(token):
    """(A) §3.6: applied:true인데 본문에 토큰 생문자열 → ③이 거부."""
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_plant("request_body", FAKES["jwt"])))
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert _status(sent) == 422 and json.loads(body) == {"error": "sanitization_rejected"}


def test_schema_valid_but_false_receipt_on_unmasked_cookie_is_rejected():
    """(A) §3.6: 스키마는 맞고 sanitization 필드만 거짓 — Cookie가 실제로는 평문."""
    env = _lying_receipt(_env())
    env = _set(env, f"{T0}.request.headers.0.value", FAKES["session_cookie_pair"])
    reasons = _reasons(env)
    assert any(r.startswith("plaintext_sensitive_header@") for r in reasons)
    assert any(r.startswith("session_cookie_pair@") for r in reasons)


# ── 위조 거부: 영수증 fail-closed ──────────────────────────────────────

@pytest.mark.parametrize("applied,failed,expected", [
    (False, False, {"receipt_not_applied"}),
    (True, True, {"receipt_failed"}),
    (False, True, {"receipt_not_applied", "receipt_failed"}),
])
def test_receipt_not_applied_or_failed_is_rejected_even_if_data_is_clean(applied, failed, expected):
    env = _env()
    env["transactions"][0]["meta"]["sanitization"].update(applied=applied, failed=failed)
    assert {r.split("@")[0] for r in _reasons(env)} == expected


@pytest.mark.parametrize("path,value", [
    (f"{T0}.meta.sanitization", _DEL),
    (f"{T0}.meta.sanitization.applied", _DEL),
    (f"{T0}.meta.sanitization.failed", _DEL),
    (f"{T0}.meta.sanitization.applied", "true"),
    (f"{T0}.meta.sanitization.failed", 0),
    (f"{T0}.meta.sanitization.redacted_kinds", ["cookie"]),
])
def test_receipt_missing_or_mistyped_is_rejected_before_recheck(token, monkeypatch, path, value):
    """필드 누락·타입 오류 → ②에서 거부, ③에는 도달조차 하지 않음(fail-closed 연속성)."""
    calls = []
    monkeypatch.setattr(sanitization_check, "verify_sanitization", lambda *a, **k: calls.append(a))
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_set(_env(), path, value)))
    assert _status(sent) == 422 and calls == []


# ── 보조 방어선: 이름 화이트리스트 ─────────────────────────────────────

@pytest.mark.parametrize("side,name", [
    ("request", "Authorization"), ("request", "aUtHoRiZaTiOn"), ("request", "Proxy-Authorization"),
    ("request", "Cookie"), ("response", "Set-Cookie"), ("request", "X-API-Key"), ("request", "X-Custom-Token"),
    ("request", "X-Client-Secret"), ("response", "X-Session-Id"),
])
def test_plaintext_whitelisted_header_is_rejected_even_without_pattern_match(side, name):
    env = _lying_receipt(_env())
    env["transactions"][0][side]["headers"].append({"name": name, "value": "opaque"})  # 패턴엔 안 걸리는 값
    assert {r.split("@")[0] for r in _reasons(env)} == {"plaintext_sensitive_header"}


def test_masked_whitelisted_header_passes():
    env = _lying_receipt(_env())
    env["transactions"][0]["request"]["headers"].append(
        {"name": "Authorization", "value": {"masked": True, "label": "ref_02", "kind": "token"}})
    verify_sanitization(parse_envelope(_raw(env)))


def test_value_rescan_does_not_depend_on_the_name_whitelist():
    """주 방어선의 독립성: 화이트리스트를 비워도 값 재스캔이 생문자열을 잡는다."""
    no_names = SanitizationPolicy(policy_version="empty", header_rules=())
    for pattern, fake in FAKES.items():
        env = _lying_receipt(_env())
        env["transactions"][0]["request"]["headers"].append({"name": "Authorization", "value": fake})
        assert any(r.startswith(f"{pattern}@") for r in _reasons(env, no_names)), pattern


def test_opaque_secret_in_unlisted_place_is_not_detected_documented_limitation():
    """정직한 한계((A) §2.3): 정책 패턴에 안 걸리는 불투명 값은 일반 문자열과 구분 불가 → 통과한다.
    이 테스트는 '모든 비밀값 부재를 증명하지 않음'을 고정해 두는 것이다(통과가 보장이 아님)."""
    env = _lying_receipt(_env())
    env["transactions"][0]["request"]["headers"].append({"name": "X-Trace", "value": secrets.token_hex(16)})
    verify_sanitization(parse_envelope(_raw(env)))


# ── 위조 거부: 본문 계약·크기 상한 ──────────────────────────────────────

def test_omitted_body_with_content_is_rejected():
    env = _set(_env(), f"{T0}.request.body.encoding", "omitted")
    assert {r.split("@")[0] for r in _reasons(env)} == {"omitted_with_content"}


@pytest.mark.parametrize("content", ["not base64!!", "abc", "YWJj\n=="])
def test_undecodable_base64_body_is_rejected(content):
    env = _env()
    env["transactions"][0]["request"]["body"].update(encoding="base64", content=content)
    assert "undecodable_base64" in {r.split("@")[0] for r in _reasons(env)}


@pytest.mark.parametrize("side,cap", [("request", REQ_BODY_CAP), ("response", RESP_BODY_CAP)])
def test_body_over_cap_is_rejected_and_at_cap_passes(side, cap):
    env = _env()
    env["transactions"][0][side]["body"].update(content="a" * cap, size_bytes=cap)
    verify_sanitization(parse_envelope(_raw(env)))
    env["transactions"][0][side]["body"].update(content="a" * (cap + 1), size_bytes=cap + 1)
    assert {r.split("@")[0] for r in _reasons(env)} == {"body_over_cap"}


def test_base64_body_cap_counts_decoded_bytes():
    env = _env()
    data = base64.b64encode(b"a" * (REQ_BODY_CAP + 1)).decode()
    env["transactions"][0]["request"]["body"].update(encoding="base64", content=data)
    assert "body_over_cap" in {r.split("@")[0] for r in _reasons(env)}


def test_oversized_http_request_is_rejected_before_parsing(token, monkeypatch):
    calls = []
    monkeypatch.setattr(schema_gate, "parse_envelope", lambda raw: calls.append(len(raw)))
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), b" " * (MAX_REQUEST_BYTES + 1))
    assert _status(sent) == 413 and calls == []


# ── 위조 거부: 감사·응답 위생, 순서 ───────────────────────────────────────

def test_rejection_audit_has_reason_codes_only_no_values_or_input_names(caplog):
    marker_name, marker_val = "X-" + secrets.token_hex(6), secrets.token_hex(8)
    env = _lying_receipt(_env())
    env["transactions"][0]["request"]["headers"].append({"name": marker_name, "value": FAKES["jwt"] + marker_val})
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        reasons = _reasons(env)
    records = [r for r in caplog.records if r.name == "sentinel.audit"]
    assert len(records) == 1 and records[0].getMessage().startswith("sanitization_rejected")
    dump = records[0].getMessage() + repr(records[0].__dict__) + ",".join(reasons)
    for secret in (marker_name, marker_val, FAKES["jwt"]):
        assert secret not in dump


def test_recheck_is_never_reached_without_token_or_valid_schema(token, monkeypatch):
    calls = []
    monkeypatch.setattr(sanitization_check, "verify_sanitization", lambda *a, **k: calls.append(a))
    _drive(create_app(token), _scope([]), _raw(_plant("request_body", FAKES["jwt"])))  # ① 실패
    _drive(create_app(token), _scope([(HEADER, token)]), b"{}")  # ② 실패
    assert calls == []
    _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))  # 대조군: ①② 통과 → ③ 호출
    assert len(calls) == 1


def test_recheck_does_not_mutate_or_trust_the_receipt():
    env = parse_envelope(_raw(_lying_receipt(_env())))
    before = copy.deepcopy(env.model_dump())
    verify_sanitization(env)
    assert env.model_dump() == before
