"""감사 로그 — `audit_log_present`. 각 거부 경로가 감사 저장소(SQLite)에 흔적을 남긴다(민감값 없이).

'위조 거부'로 증명한다: 인증 실패·스키마 거부·재검증 거부·요청 크기 초과·egress 시도 각각이 저장소에 행을
남기고, 그 어느 행에도 토큰·제시 토큰·본문·입력 헤더명·egress 목적지가 들어가지 않는다.
감사 기록 실패 시 fail-closed(`audit_write_failure`)는 수용 요청 감사(B-6) 범위 확정 시 — 현재 동작(요청을 막지 않음)을 고정해 둔다.
"""
from __future__ import annotations

import logging
import secrets
import sys

import pytest
import uvicorn

import sentinel.server.serve as serve_mod
from sentinel.audit import (
    AUDIT_DB_ENV, attach_audit_store, audit_log, detach_audit_store, install_egress_audit_hook, read_audit_events)
from sentinel.server.app import MAX_REQUEST_BYTES, create_app
from sentinel.server.auth import TOKEN_ENV
from sentinel.server.config import ServerConfig
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_sanitization import FAKES, _plant
from tests.test_schema import T0, _env, _raw, _set


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "audit.sqlite3"
    handler = attach_audit_store(path)
    yield path
    detach_audit_store(handler)


def _events(path) -> list[str]:
    return [e["event"] for e in read_audit_events(path)]


def _dump(path) -> str:
    return "\n".join(repr(e) for e in read_audit_events(path))


# ── 각 거부 경로가 저장소에 남는다 ──────────────────────────────────────

def test_auth_failure_is_persisted(store, token):
    _drive(create_app(token), _scope([]), _raw(_env()))
    assert _events(store) == ["auth_failure"]


def test_schema_rejection_is_persisted(store, token):
    _drive(create_app(token), _scope([(HEADER, token)]), b"{}")
    assert _events(store) == ["schema_rejected"]


def test_sanitization_rejection_is_persisted(store, token):
    _drive(create_app(token), _scope([(HEADER, token)]), _raw(_plant("request_body", FAKES["jwt"])))
    assert _events(store) == ["sanitization_rejected"]


def test_oversized_request_is_persisted(store, token):
    _drive(create_app(token), _scope([(HEADER, token)]), b" " * (MAX_REQUEST_BYTES + 1))
    assert _events(store) == ["payload_too_large"]


def test_egress_attempt_is_persisted_without_destination(store):
    """런타임 감사 훅이 외부 목적지 소켓 이벤트를 관측해 기록(차단 아님). 실제 송신 없이 감사 이벤트만 발생."""
    install_egress_audit_hook()
    host = f"egress-{secrets.token_hex(4)}.invalid"
    sys.audit("socket.getaddrinfo", host, 443, 0, 0, 0)
    sys.audit("socket.connect", None, ("192.0.2.1", 8443))
    sys.audit("socket.sendto", None, ("192.0.2.1", 53))
    assert _events(store) == ["egress_attempt"] * 3
    dump = _dump(store)
    assert "op=resolve" in dump and "op=connect" in dump and "op=sendto" in dump
    assert host not in dump and "192.0.2.1" not in dump  # 목적지 미기록


def test_local_socket_events_are_not_audited_as_egress(store):
    install_egress_audit_hook()
    sys.audit("socket.connect", None, ("127.0.0.1", 8765))
    sys.audit("socket.getaddrinfo", "localhost", 8765, 0, 0, 0)
    sys.audit("socket.connect", None, "/tmp/sentinel.sock")  # AF_UNIX
    assert _events(store) == []


def test_accepted_request_leaves_no_rejection_trace(store, token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
    assert _status(sent) == 200 and _events(store) == []


def test_audit_survives_handler_restart(tmp_path, token):
    path = tmp_path / "audit.sqlite3"
    handler = attach_audit_store(path)
    _drive(create_app(token), _scope([]), b"")
    detach_audit_store(handler)
    handler = attach_audit_store(path)
    _drive(create_app(token), _scope([]), b"")
    detach_audit_store(handler)
    assert _events(path) == ["auth_failure", "auth_failure"]


# ── 위조 거부: 저장소에 민감값이 새지 않는다 ─────────────────────────────

def test_persisted_audit_contains_no_sensitive_values(store, token):
    presented = secrets.token_urlsafe(32).encode()
    body_marker = secrets.token_hex(12)
    header_marker = "X-" + secrets.token_hex(6)
    app = create_app(token)
    _drive(app, _scope([(HEADER, presented)], query=b"q=" + body_marker.encode()), body_marker.encode())
    _drive(app, _scope([(HEADER, token)]), _raw(_set(_env(), f"{T0}.request.port", body_marker)))
    env = _plant("request_body", FAKES["jwt"])
    env["transactions"][0]["request"]["headers"].append({"name": header_marker, "value": FAKES["aws_access_key_id"]})
    _drive(app, _scope([(HEADER, token)]), _raw(env))
    assert _events(store) == ["auth_failure", "schema_rejected", "sanitization_rejected"]
    dump = _dump(store)
    for secret in (token.decode(), presented.decode(), body_marker, header_marker,
                   FAKES["jwt"], FAKES["aws_access_key_id"]):
        assert secret not in dump


# ── 기동 시 설치 ───────────────────────────────────────────────────

def test_serve_attaches_audit_store_and_egress_hook(monkeypatch, tmp_path, token):
    path = tmp_path / "srv-audit.sqlite3"
    monkeypatch.setenv(TOKEN_ENV, token.decode())
    monkeypatch.setenv(AUDIT_DB_ENV, str(path))
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, *a, **k: None)
    before = list(audit_log.handlers)
    serve_mod.serve(ServerConfig(port=0))
    added = [h for h in audit_log.handlers if h not in before]
    try:
        assert len(added) == 1 and path.exists()
        audit_log.warning("auth_failure reason=missing scope=http method=POST route=/v1/analyze")
        assert _events(path) == ["auth_failure"]
    finally:
        for h in added:
            detach_audit_store(h)


# ── 정직한 한계: 기록 실패 시 fail-closed는 수용 요청 감사(B-6) 범위 확정 시 ─────────────────

def test_audit_write_failure_does_not_block_requests_yet_documented(tmp_path, token, monkeypatch):
    """`audit_write_failure`(not_implemented→수용 요청 감사(B-6) 범위 확정 시)의 현재 동작을 고정: 저장 실패해도 요청 처리는 계속된다.
    '못 남기면 거부'는 1주차에 미정의 — 이 테스트는 그 사실을 드러내 두는 것이다(보장이 아님)."""
    monkeypatch.setattr(logging, "raiseExceptions", False)  # handleError 출력 억제(테스트 소음)
    handler = attach_audit_store(tmp_path / "broken.sqlite3")
    handler._conn.close()  # 저장소 고장 모의
    try:
        sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _raw(_env()))
        assert _status(sent) == 200
        sent, _ = _drive(create_app(token), _scope([]), b"")
        assert _status(sent) == 401
    finally:
        audit_log.removeHandler(handler)
