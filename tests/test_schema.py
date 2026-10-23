"""파이프라인 ② 스키마 검증 — `input_schema_gate` · `envelope_arity` · `maskedref_typing`.

'위조 거부'로 증명한다: arity 위반, 계약 밖 구조·형 변환 우회, MaskedRef에 원문 밀반입을 거부하고,
거부 감사·응답에 입력 값이 남지 않음을 확인한다. 테스트 데이터는 Juice Shop 형태의 더미(N5),
토큰 형태 값은 런타임 생성(N7).
"""
from __future__ import annotations

import copy
import json
import logging
import secrets
from typing import Any

import pytest

from sentinel.pipeline import schema_gate
from sentinel.pipeline.schema_gate import SchemaRejected, parse_envelope
from sentinel.schema import Envelope, MaskedRef
from sentinel.server.app import create_app
from tests.test_auth import HEADER, _drive, _scope, _status

BODY = {"content_type": "application/json", "size_bytes": 2, "truncated": False, "encoding": "utf8", "content": "{}"}
TX: dict[str, Any] = {
    "meta": {"transaction_id": "7f9c0f5e-3a51-4f0e-9a43-2d7b1c2f9e10", "captured_at": "2026-10-23T10:00:00+09:00",
             "origin_ref": "burp-1",
             "sanitization": {"applied": True, "failed": False, "policy_version": "p1", "redacted_count": 1,
                              "redacted_kinds": {"token": 0, "cookie": 1, "pii": 0, "host": 0}}},
    "request": {"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": 3000,
                "path": "/rest/products/search",
                "query_params": [{"name": "q", "value": "apple", "location": "query"}],
                "headers": [{"name": "Cookie", "value": {"masked": True, "label": "session_01", "kind": "cookie"}}],
                "body": dict(BODY)},
    "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}], "body": dict(BODY),
                 "elapsed_ms": 12},
}
ENVELOPE: dict[str, Any] = {"schema_version": "1.0", "analysis_type": "single", "transactions": [TX]}


def _env() -> dict[str, Any]:
    return copy.deepcopy(ENVELOPE)


def _raw(doc: Any) -> bytes:
    return json.dumps(doc).encode()


def _set(doc: dict, path: str, value: Any) -> dict:
    """점 경로로 값 설정(숫자는 리스트 인덱스). value가 _DEL이면 삭제."""
    *parents, last = path.split(".")
    node: Any = doc
    for p in parents:
        node = node[int(p)] if p.isdigit() else node[p]
    key: Any = int(last) if last.isdigit() else last
    if value is _DEL:
        del node[key]
    else:
        node[key] = value
    return doc


_DEL = object()
T0 = "transactions.0"


# ── 정상 ──────────────────────────────────────────────────────────

def test_valid_envelope_passes():
    env = parse_envelope(_raw(_env()))
    assert isinstance(env, Envelope)
    assert isinstance(env.transactions[0].request.headers[0].value, MaskedRef)


def test_valid_envelope_reaches_the_not_implemented_path_after_token(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    assert _status(sent) == 501


# ── 위조 거부: arity ───────────────────────────────────────────────

@pytest.mark.parametrize("count", [0, 2, 3])
def test_rejects_single_envelope_without_exactly_one_transaction(count):
    env = _env()
    env["transactions"] = [copy.deepcopy(TX) for _ in range(count)]
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(env))


def test_rejects_unknown_analysis_type_until_p1():
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_set(_env(), "analysis_type", "diff")))


# ── 위조 거부: 스키마 위반·형 변환 우회 ─────────────────────────────────

VIOLATIONS = {
    "missing_schema_version": ("schema_version", _DEL),
    "wrong_schema_version": ("schema_version", "1.1"),
    "extra_top_field": ("findings", []),
    "missing_meta": (f"{T0}.meta", _DEL),
    "extra_nested_field": (f"{T0}.request.raw_bytes", "x"),
    "bad_uuid": (f"{T0}.meta.transaction_id", "not-a-uuid"),
    "naive_timestamp": (f"{T0}.meta.captured_at", "2026-10-23T10:00:00"),
    "scheme_ftp": (f"{T0}.request.scheme", "ftp"),
    "port_as_string": (f"{T0}.request.port", "3000"),
    "port_out_of_range": (f"{T0}.request.port", 70000),
    "port_as_float": (f"{T0}.request.port", 3000.0),
    "status_out_of_range": (f"{T0}.response.status", 99),
    "negative_size": (f"{T0}.request.body.size_bytes", -1),
    "truncated_as_string": (f"{T0}.request.body.truncated", "false"),
    "truncated_as_int": (f"{T0}.request.body.truncated", 0),
    "unknown_encoding": (f"{T0}.request.body.encoding", "gzip"),
    "content_not_string": (f"{T0}.request.body.content", 123),
    "unknown_param_location": (f"{T0}.request.query_params.0.location", "header"),
    "unknown_redacted_kind": (f"{T0}.meta.sanitization.redacted_kinds.password", 1),
    "redacted_kinds_as_list": (f"{T0}.meta.sanitization.redacted_kinds", ["cookie"]),
    "redacted_kind_missing": (f"{T0}.meta.sanitization.redacted_kinds.host", _DEL),
    "redacted_kind_negative": (f"{T0}.meta.sanitization.redacted_kinds.token", -1),
    "redacted_kind_as_string": (f"{T0}.meta.sanitization.redacted_kinds.pii", "0"),
    "negative_redacted_count": (f"{T0}.meta.sanitization.redacted_count", -1),
    "applied_as_string": (f"{T0}.meta.sanitization.applied", "true"),
    "missing_sanitization": (f"{T0}.meta.sanitization", _DEL),
    "elapsed_negative": (f"{T0}.response.elapsed_ms", -5),
    "headers_not_list": (f"{T0}.request.headers", {"Cookie": "x"}),
}


@pytest.mark.parametrize("name", sorted(VIOLATIONS))
def test_rejects_schema_violation(name):
    path, value = VIOLATIONS[name]
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_set(_env(), path, value)))


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b'"envelope"', b"{", b"\xff\xfe", b"NaN"])
def test_rejects_non_envelope_bytes(raw):
    with pytest.raises(SchemaRejected):
        parse_envelope(raw)


# ── 위조 거부: MaskedRef에 원문 밀반입 ──────────────────────────────────

def _smuggles() -> dict[str, Any]:
    raw = secrets.token_urlsafe(24)  # 원문 토큰을 흉내 낸 런타임 값
    ok = {"masked": True, "label": "session_01", "kind": "cookie"}
    return {
        "extra_value_field": {**ok, "value": raw},
        "extra_original_field": {**ok, "original": raw},
        "label_is_raw_token": {**ok, "label": raw},
        "label_with_space": {**ok, "label": "Bearer abc_01"},
        "label_uppercase": {**ok, "label": "Session_01"},
        "label_one_digit": {**ok, "label": "session_1"},
        "label_too_long": {**ok, "label": "a" * 40 + "_01"},
        "masked_false": {**ok, "masked": False},
        "masked_string": {**ok, "masked": "true"},
        "masked_int": {**ok, "masked": 1},
        "masked_missing": {k: v for k, v in ok.items() if k != "masked"},
        "unknown_kind": {**ok, "kind": "password"},
        "kind_missing": {k: v for k, v in ok.items() if k != "kind"},
        "label_not_string": {**ok, "label": 1},
    }


SMUGGLE_KINDS = sorted(_smuggles())


@pytest.mark.parametrize("kind", SMUGGLE_KINDS)
@pytest.mark.parametrize("slot", [f"{T0}.request.headers.0.value", f"{T0}.request.query_params.0.value",
                                  f"{T0}.response.headers.0.value"])
def test_rejects_raw_string_smuggled_into_masked_ref(kind, slot):
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_set(_env(), slot, _smuggles()[kind])))


def test_masked_ref_type_has_no_field_that_can_carry_a_raw_value():
    assert set(MaskedRef.model_fields) == {"masked", "label", "kind"}
    assert MaskedRef.model_config["extra"] == "forbid" and MaskedRef.model_config["frozen"] is True
    ok = MaskedRef(masked=True, label=None, kind="token")
    with pytest.raises(Exception):
        ok.label = secrets.token_urlsafe(24)  # type: ignore[misc] — 불변


def test_null_label_is_allowed_as_contract_says():
    """(A) §2.3: label은 "principal_01" | null."""
    env = _set(_env(), f"{T0}.request.headers.0.value", {"masked": True, "label": None, "kind": "token"})
    assert parse_envelope(_raw(env)).transactions[0].request.headers[0].value.label is None


# ── 위조 거부: 거부 감사·응답에 입력 값 없음 ──────────────────────────────

def test_schema_rejection_is_audited_without_input_values(caplog):
    marker_key, marker_val = "k" + secrets.token_hex(8), secrets.token_urlsafe(24)
    env = _set(_env(), f"{T0}.request.{marker_key}", marker_val)
    env = _set(env, f"{T0}.request.headers.0.value", {"masked": True, "label": marker_val, "kind": "token"})
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        with pytest.raises(SchemaRejected) as exc:
            parse_envelope(_raw(env))
    records = [r for r in caplog.records if r.name == "sentinel.audit"]
    assert len(records) == 1 and records[0].getMessage().startswith("schema_rejected")
    dump = records[0].getMessage() + repr(records[0].__dict__) + str(exc.value)
    assert marker_key not in dump and marker_val not in dump
    assert exc.value.__cause__ is None and exc.value.__suppress_context__  # 원 ValidationError 체인 끊음


def test_http_schema_rejection_returns_422_without_reflecting_input(token):
    marker = secrets.token_urlsafe(24)
    env = _set(_env(), f"{T0}.request.port", marker)
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(env))
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert _status(sent) == 422
    assert json.loads(body) == {"error": "schema_rejected"} and marker.encode() not in body


# ── 순서: ① 토큰 → ② 스키마 ──────────────────────────────────────────

def test_schema_gate_is_never_reached_without_token(token, monkeypatch):
    calls = []
    monkeypatch.setattr(schema_gate, "parse_envelope", lambda raw: calls.append(raw))
    sent, received = _drive(create_app(token), _scope([]), b"not even json")
    assert _status(sent) == 401 and calls == [] and received == 0


def test_schema_gate_is_reached_after_token(token, monkeypatch):
    """대조군: 토큰 통과 시 스키마 게이트가 실제로 호출됨(모듈.함수 경로 — 스파이 우회 없음)."""
    calls = []
    real = schema_gate.parse_envelope
    monkeypatch.setattr(schema_gate, "parse_envelope", lambda raw: calls.append(raw) or real(raw))
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    assert _status(sent) == 501 and calls == [_raw(_env())]
