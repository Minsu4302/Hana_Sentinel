"""파이프라인 ② 스키마 검증 — `input_schema_gate` · `envelope_arity` · `maskedref_typing` · `path_no_query_string`.

'위조 거부'로 증명한다: arity 위반, 계약 밖 구조·형 변환 우회, MaskedRef에 원문 밀반입을 거부하고,
거부 감사·응답에 입력 값이 남지 않음을 확인한다. 테스트 데이터는 Juice Shop 형태의 더미(N5),
토큰 형태 값은 런타임 생성(N7).
변이 확인은 tools.mutation_guard로 '치환 성공 + 실행 중 로드된 모듈 = 변이본'을 먼저 증명한다.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sentinel.pipeline import execution, sanitization_check, schema_gate
from sentinel.pipeline.schema_gate import SchemaRejected, parse_envelope
from sentinel.common_types import MaskedRef
from sentinel.schema import Envelope
from sentinel.server.app import create_app
from tests.test_auth import HEADER, _drive, _scope, _status
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]

BODY = {"content_type": "application/json", "size_bytes": 2, "truncated": False, "encoding": "utf8", "content": "{}"}
TX: dict[str, Any] = {
    "meta": {"transaction_id": "7f9c0f5e-3a51-4f0e-9a43-2d7b1c2f9e10", "captured_at": "2026-10-23T10:00:00+09:00",
             "origin_ref": "burp-1",
             "sanitization": {"applied": True, "failed": False, "policy_version": "p1", "redacted_count": 1,
                              "redacted_kinds": {"token": 0, "cookie": 1, "pii": 0, "host": 0}}},
    "request": {"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": 3000,
                "path": "/rest/products/search",
                "query_params": [{"name": "q", "value": "apple", "location": "query"}],
                "headers": [{"name": "Cookie", "value": {"masked": True, "label": "ref_01", "kind": "cookie"}}],
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
    assert _status(sent) == 200


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
    "removed_param_location_json": (f"{T0}.request.query_params.0.location", "json"),  # (A) v1.9 §2.2 축소
    "removed_param_location_path": (f"{T0}.request.query_params.0.location", "path"),
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
    ok = {"masked": True, "label": "ref_01", "kind": "cookie"}
    return {
        "extra_value_field": {**ok, "value": raw},
        "extra_original_field": {**ok, "original": raw},
        "label_is_raw_token": {**ok, "label": raw},
        "label_with_space": {**ok, "label": "ref _01"},
        "label_uppercase": {**ok, "label": "REF_01"},
        "label_one_digit": {**ok, "label": "ref_1"},
        "label_too_many_digits": {**ok, "label": "ref_01234"},
        "label_not_digits": {**ok, "label": "ref_abc"},
        "label_old_semantic_prefix": {**ok, "label": "principal_01"},  # (A) §2.3: 의미 있는 접두사 금지(ref만)
        "label_trailing_newline": {**ok, "label": "ref_01\n"},
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
    """(A) §2.6: label은 "ref_NN" | null."""
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
    assert _status(sent) == 200 and calls == [_raw(_env())]


# ── 위조 거부: request.path에 쿼리 문자열(raw '?') — `path_no_query_string`, (A) §2.2 ─────────

RAW_QUERY_PATHS = {
    "query_appended": "/rest/products/search?q=apple",
    "trailing": "/rest/products/search?",
    "middle": "/rest/?/search",
    "alone": "?",
}
ENCODED_QUERY_PATHS = {
    "encoded_upper": "/rest/products/a%3Fb",
    "encoded_lower": "/rest/products/a%3fb",
    "encoded_trailing": "/rest/products/search%3F",
}


def _with_path(path: str) -> dict[str, Any]:
    return _set(_env(), f"{T0}.request.path", path)


@pytest.mark.parametrize("name", sorted(RAW_QUERY_PATHS))
def test_rejects_raw_question_mark_in_path(name):
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_with_path(RAW_QUERY_PATHS[name])))


@pytest.mark.parametrize("name", sorted(ENCODED_QUERY_PATHS))
def test_percent_encoded_question_mark_in_path_is_accepted(name):
    """대조(과잉 거부 방지): 판정은 디코딩 전 raw 문자열 — '%3F'는 경로 세그먼트의 정상 일부."""
    env = parse_envelope(_raw(_with_path(ENCODED_QUERY_PATHS[name])))
    assert env.transactions[0].request.path == ENCODED_QUERY_PATHS[name]  # 디코딩하지 않고 그대로 보존


def test_query_is_accepted_as_query_params():
    """대조: 같은 쿼리를 path가 아니라 query_params(location=query)로 보내면 정상 수용."""
    req = parse_envelope(_raw(_env())).transactions[0].request
    assert req.path == "/rest/products/search" and "?" not in req.path
    assert [(p.name, p.value, p.location) for p in req.query_params] == [("q", "apple", "query")]


def _stage_recorders(monkeypatch) -> list[str]:
    calls: list[str] = []
    for module, name in ((schema_gate, "parse_envelope"), (sanitization_check, "verify_sanitization"),
                         (execution, "build_execution_response")):
        real = getattr(module, name)
        monkeypatch.setattr(module, name, lambda *a, _n=name, _r=real, **k: calls.append(_n) or _r(*a, **k))
    return calls


def test_raw_question_mark_is_rejected_in_schema_stage_without_reflecting_input(token, monkeypatch, caplog):
    """② 안에서 거부: 스키마 단계는 불렸고 ③ sanitization·④ 실행은 미호출. 응답·감사에 path 값 없음."""
    marker = secrets.token_hex(8)
    calls = _stage_recorders(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        sent, _ = _drive(create_app(token), _scope([(HEADER, token)]),
                         _raw(_with_path(f"/rest/{marker}?q={marker}")))
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert _status(sent) == 422 and json.loads(body) == {"error": "schema_rejected"}
    assert calls == ["parse_envelope"]
    audit = [r.getMessage() for r in caplog.records if r.name == "sentinel.audit"]
    assert audit and all(marker not in m for m in audit) and marker.encode() not in body


def test_encoded_question_mark_passes_every_stage(token, monkeypatch):
    """대조: '%3F' path는 ②뿐 아니라 ③ 재검증도 통과해 ④까지 간다(어느 단계도 과잉 거부하지 않음)."""
    calls = _stage_recorders(monkeypatch)
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_with_path("/rest/products/a%3Fb")))
    assert _status(sent) == 200
    assert calls == ["parse_envelope", "verify_sanitization", "build_execution_response"]


def test_token_check_precedes_question_mark_check(token, monkeypatch):
    """순서 불변(① → ②): 토큰이 없으면 '?' 검사(스키마 단계) 전에 401. 토큰이 있으면 같은 본문이 ②에서 422."""
    calls = _stage_recorders(monkeypatch)
    raw = _raw(_with_path("/rest/products/search?q=apple"))
    sent, received = _drive(create_app(token), _scope([]), raw)
    assert _status(sent) == 401 and calls == [] and received == 0
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), raw)
    assert _status(sent) == 422 and calls == ["parse_envelope"]


# ── 변이 확인: '?' 검사가 하중을 지지하고, 과잉 거부 방지(%3F 대조)도 하중을 진다 ─────────────

STAMP = "path_query_probe"
_DRIVER = """
import sys, pytest
import sentinel.schema  # pytest의 pythonpath 삽입 전에 변이본을 먼저 적재
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_schema.py::"
MUTATIONS = {
    # '?' 검사 무력화 → raw '?' path가 통과
    "question_mark_check_off": ('        if "?" in v:\n', "        if False:\n",
                                [_T + "test_rejects_raw_question_mark_in_path"]),
    # 디코딩 후 판정(과잉 거부) → '%3F'까지 거부
    "rejects_encoded_too": ('        if "?" in v:\n', '        if "?" in v or "%3f" in v.lower():\n',
                            [_T + "test_percent_encoded_question_mark_in_path_is_accepted"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_path_query_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], tmp_path / "mut" / "src",
                                "sentinel/schema.py", old, new)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut" / "src"), str(REPO_ROOT)]),
           "PYTHONUTF8": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), "sentinel.schema", *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
