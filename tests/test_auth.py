"""토큰 게이트 — `request_token_validation` · `auth_precedence_noinvoke` · `authfail_log_hygiene`.

'401이 나온다'에 그치지 않고 '그 뒤가 호출되지 않았다'를 스파이로 증명한다: 인증 실패 시
하위 앱(라우팅·파서·분석·저장으로 가는 유일한 진입로), 요청 본문 수신(ASGI receive), 본문 읽기·역직렬화
함수(Request.body/json/form/stream, json.loads, pydantic 검증)가 한 번도 불리지 않는다.
토큰은 전부 런타임 생성(하드코딩 금지, N7).
"""
from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
import json
import logging
import pkgutil
import secrets
import socket

import pydantic
import pytest
import starlette.requests
import uvicorn
from fastapi import FastAPI

import sentinel.pipeline
import sentinel.server.auth as auth
import sentinel.server.serve as serve_mod
from sentinel.server.__main__ import main as cli_main
from sentinel.server.app import ANALYZE_PATH, create_app
from sentinel.server.auth import TOKEN_ENV, TOKEN_HEADER, TokenConfigError, TokenGate, load_shared_token
from sentinel.server.config import BIND_HOST, ServerConfig
from sentinel.server.serve import LoopbackOnlyServer, build_uvicorn_config
from tests.test_server import _Run

HEADER = TOKEN_HEADER.lower().encode()


def _scope(headers=(), *, path=ANALYZE_PATH, method="POST", query=b"", kind="http") -> dict:
    return {"type": kind, "method": method, "path": path, "raw_path": path.encode(), "query_string": query,
            "headers": [(k.lower(), v) for k, v in headers], "http_version": "1.1", "scheme": "http",
            "server": (BIND_HOST, 8765), "client": (BIND_HOST, 50000), "root_path": "", "asgi": {"version": "3.0"}}


def _drive(app, scope, body=b"") -> tuple[list[dict], int]:
    """ASGI 앱을 직접 호출. (보낸 메시지, receive 호출 횟수)를 돌려준다."""
    sent: list[dict] = []
    received = 0

    async def receive():
        nonlocal received
        received += 1
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent, received


def _status(sent) -> int:
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


class SpyApp:
    """하위 앱 스파이 — 호출되면 본문을 읽는다(실제 파서가 하듯)."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def _forged_requests(token: bytes) -> dict[str, dict]:
    """토큰 없음·위조 변형 — 전부 거부돼야 한다."""
    wrong = secrets.token_urlsafe(32).encode()
    return {
        "missing": {"headers": []},
        "empty": {"headers": [(HEADER, b"")]},
        "wrong": {"headers": [(HEADER, wrong)]},
        "prefix": {"headers": [(HEADER, token[:-1])]},
        "suffix": {"headers": [(HEADER, token + b"x")]},
        "case_changed": {"headers": [(HEADER, token.swapcase())]},
        "padded": {"headers": [(HEADER, b" " + token)]},
        "duplicate_valid": {"headers": [(HEADER, token), (HEADER, token)]},
        "duplicate_mixed": {"headers": [(HEADER, wrong), (HEADER, token)]},
        "other_header": {"headers": [(b"authorization", b"Bearer " + token)]},
        "query_string": {"headers": [], "query": b"token=" + token},
        "body_only": {"headers": [], "body": token},
    }


FORGED_KINDS = list(_forged_requests(b"placeholder-not-used"))


# ── 정상: 유효 토큰만 하위로 ─────────────────────────────────────────

def test_valid_token_reaches_downstream(token):
    spy = SpyApp()
    sent, received = _drive(TokenGate(spy, token), _scope([(HEADER, token)]))
    assert _status(sent) == 200 and spy.calls == 1 and received == 1


def _valid_envelope() -> bytes:
    from tests.test_schema import ENVELOPE  # 지연 import(순환 방지) — 정상 Envelope 더미
    return json.dumps(ENVELOPE).encode()


def test_valid_token_reaches_the_pipeline(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _valid_envelope())
    assert _status(sent) == 200  # ①②③ 통과 → ④ ExecutionResponse


# ── 위조 거부: 토큰 없음·위조 → 401 + 하위·본문 미호출 ─────────────────────

@pytest.mark.parametrize("kind", FORGED_KINDS)
def test_forged_or_missing_token_is_rejected_before_downstream_and_body(token, kind):
    req = _forged_requests(token)[kind]
    spy = SpyApp()
    sent, received = _drive(TokenGate(spy, token), _scope(req["headers"], query=req.get("query", b"")),
                            req.get("body", b""))
    assert _status(sent) == 401
    assert spy.calls == 0  # 하위 앱(라우팅·파서·분석·저장의 유일 진입로) 미호출
    assert received == 0  # 요청 본문을 받지조차 않음


def pipeline_functions() -> list[tuple[object, str]]:
    """`sentinel.pipeline` 패키지의 모든 함수를 자동 열거 — 새 단계 함수는 수동 등록 없이 스파이 대상이 된다
    (W1-04 회귀 리스크: 알려진 함수만 감시하면 새 함수가 생길 때 enforced가 조용히 낡음)."""
    found = []
    for info in pkgutil.walk_packages(sentinel.pipeline.__path__, "sentinel.pipeline."):
        module = importlib.import_module(info.name)
        for name, fn in inspect.getmembers(module, inspect.isfunction):
            if fn.__module__ == module.__name__:
                found.append((module, name))
    return found


PIPELINE_FUNCTIONS = pipeline_functions()  # 스파이 패치 전에 열거(패치된 래퍼는 __module__이 바뀜)


@pytest.fixture
def parse_spies(monkeypatch):
    """본문 읽기·역직렬화·파이프라인 단계 스파이(실제 FastAPI 앱 안쪽). 호출되면 기록된다."""
    hits: list[str] = []

    def spy(name, original):
        def wrapper(*a, **k):
            hits.append(name)
            return original(*a, **k)
        return wrapper

    for module, name in PIPELINE_FUNCTIONS:
        monkeypatch.setattr(module, name, spy(f"{module.__name__}.{name}", getattr(module, name)))

    for name in ("body", "json", "form", "stream"):
        monkeypatch.setattr(starlette.requests.Request, name, spy(f"Request.{name}",
                                                                  getattr(starlette.requests.Request, name)))
    monkeypatch.setattr(json, "loads", spy("json.loads", json.loads))
    for name in ("model_validate", "model_validate_json"):
        monkeypatch.setattr(pydantic.BaseModel, name, classmethod(spy(f"BaseModel.{name}",
                                                                      getattr(pydantic.BaseModel, name).__func__)))
    return hits


@pytest.mark.parametrize("kind", FORGED_KINDS)
def test_real_app_never_invokes_inner_app_parser_or_deserializer_on_auth_failure(token, kind, parse_spies):
    req = _forged_requests(token)[kind]
    app = create_app(token)
    parse_spies.clear()  # 앱 구성 시점(manifest 파일 읽기)은 요청 처리가 아님 — 요청 구간만 검사
    inner_calls: list[dict] = []
    real_inner = app.app

    async def inner_spy(scope, receive, send):
        inner_calls.append(scope)
        await real_inner(scope, receive, send)

    app.app = inner_spy
    sent, received = _drive(app, _scope(req["headers"], query=req.get("query", b"")),
                            req.get("body", b'{"transactions": []}'))
    assert _status(sent) == 401
    assert inner_calls == [] and received == 0 and parse_spies == []


def test_parse_spies_do_detect_body_parsing_as_control(token, parse_spies):
    """대조군: 스파이가 실제로 파싱을 잡아낸다(위 '미호출' 증명이 고장 난 스파이 덕이 아님)."""
    api = FastAPI()

    @api.post("/echo")
    async def echo(request: starlette.requests.Request):
        return await request.json()

    sent, received = _drive(TokenGate(api, token), _scope([(HEADER, token)], path="/echo"), b'{"a": 1}')
    assert _status(sent) == 200 and received >= 1
    assert "Request.json" in parse_spies and "Request.body" in parse_spies


def test_pipeline_spies_cover_every_stage_function_and_detect_calls_as_control(token, parse_spies):
    """대조군: 자동 열거가 비어 있지 않고, 토큰 통과 시 앱이 파이프라인 함수를 '모듈.함수'로 호출해
    스파이에 잡힌다(직접 import로 묶어 스파이를 우회하면 이 테스트가 실패)."""
    stages = {f"{m.__name__}.{n}" for m, n in PIPELINE_FUNCTIONS}
    assert "sentinel.pipeline.schema_gate.parse_envelope" in stages
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), _valid_envelope())
    assert _status(sent) == 200
    assert "sentinel.pipeline.schema_gate.parse_envelope" in parse_spies
    assert "BaseModel.model_validate_json" in parse_spies


def test_websocket_scope_is_rejected_without_calling_downstream(token):
    spy = SpyApp()
    sent, received = _drive(TokenGate(spy, token), _scope([(HEADER, token)], kind="websocket"))
    assert sent == [{"type": "websocket.close", "code": 1008}] and spy.calls == 0 and received == 0


def test_comparison_is_constant_time(token, monkeypatch):
    calls: list[tuple[int, int]] = []
    real = auth.hmac.compare_digest
    monkeypatch.setattr(auth.hmac, "compare_digest", lambda a, b: calls.append((len(a), len(b))) or real(a, b))
    gate = TokenGate(SpyApp(), token)
    _drive(gate, _scope([(HEADER, token)]))
    _drive(gate, _scope([(HEADER, b"short")]))
    assert calls == [(32, 32), (32, 32)]  # 다이제스트끼리 비교 — 제시 길이와 무관하게 동일 길이


# ── 실제 서버(루프백) 통합 ─────────────────────────────────────────────

@pytest.fixture
def live(monkeypatch, token):
    monkeypatch.setenv(TOKEN_ENV, token.decode())
    run = _Run(LoopbackOnlyServer(build_uvicorn_config(ServerConfig(port=0)))).start()
    assert run.server.started, run.error
    yield serve_mod.bound_addresses(run.server)[0][1]
    run.stop()


def _open_expect_continue(port, headers: dict[str, str], body: bytes) -> tuple[socket.socket, str]:
    """`Expect: 100-continue`로 요청 머리만 보내고 본문은 보내지 않은 채 첫 응답 줄을 읽는다.

    uvicorn은 앱이 본문 수신(receive)을 호출할 때만 `100 Continue`를 보낸다. 그래서 첫 줄이 곧바로 401이면
    서버가 본문을 요청하지 않고 거부한 것이다. 본문을 미리 보내면 인증 실패 시 서버가 미수신 본문을 남긴 채
    연결을 닫아 Windows가 RST로 클라이언트 전송을 끊는다(WinError 10053/10054 간헐 실패, Issue #35) — 그래서
    인증 실패 확인은 본문을 보내기 전에 응답을 읽는다. 연결 오류는 잡지 않는다(서버가 죽은 경우와 구별되게).
    """
    head = [f"POST {ANALYZE_PATH} HTTP/1.1", f"Host: {BIND_HOST}:{port}", "Content-Type: application/json",
            f"Content-Length: {len(body)}", "Expect: 100-continue", "Connection: close",
            *(f"{k}: {v}" for k, v in headers.items()), "", ""]
    sock = socket.create_connection((BIND_HOST, port), timeout=5)
    sock.sendall("\r\n".join(head).encode("latin-1"))
    return sock, _read_head(sock).split(b"\r\n", 1)[0].decode("latin-1")


def _read_head(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        assert chunk, f"응답 머리 전에 연결이 닫힘: {data!r}"
        data += chunk
    return data


def test_live_server_requires_token(live, token, parse_spies):
    """실서버: 토큰 없음·위조 → 본문을 요청하지도 않고(100 Continue 없음) 401, 하위 앱·본문 읽기·역직렬화 미호출."""
    before = list(parse_spies)  # 앱 구성 시점 기록과 분리 — 요청 구간만 본다
    body = _valid_envelope()
    for headers in ({}, {TOKEN_HEADER: secrets.token_urlsafe(32)}):
        sock, first = _open_expect_continue(live, headers, body)
        sock.close()
        assert first.split()[:2] == ["HTTP/1.1", "401"], first
    assert parse_spies == before

    # 대조군: 유효 토큰이면 서버가 본문을 요청한다(100 Continue) → 본문 전송 → ExecutionResponse(200)
    sock, first = _open_expect_continue(live, {TOKEN_HEADER: token.decode()}, body)
    with sock:
        assert first.split()[:2] == ["HTTP/1.1", "100"], first
        sock.sendall(body)
        final = _read_head(sock).split(b"\r\n", 1)[0].decode("latin-1")
    assert final.split()[:2] == ["HTTP/1.1", "200"], final
    assert "sentinel.pipeline.schema_gate.parse_envelope" in parse_spies


# ── 위조 거부: 서버 측 토큰 미설정·빈값 → 기동 거부 ─────────────────────────

BAD_ENV = [None, "", " ", "\t", "two words", "trailing\n", "\x07ctrl", "비ASCII토큰"]  # NUL은 OS가 env에 못 담음


@pytest.mark.parametrize("value", BAD_ENV)
def test_missing_or_invalid_server_token_refuses_startup(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(TOKEN_ENV, raising=False)
    else:
        monkeypatch.setenv(TOKEN_ENV, value)
    ran = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, *a, **k: ran.append(self))
    with pytest.raises(TokenConfigError) as exc:
        serve_mod.serve(ServerConfig(port=0))
    assert ran == []  # uvicorn 미기동
    if value and value.strip():
        assert value not in str(exc.value)  # 오류 메시지에 토큰 값 없음
    with pytest.raises(TokenConfigError):
        cli_main(["--port", "0"])


def test_no_unauthenticated_app_construction_path(token):
    with pytest.raises(TypeError):
        create_app()  # type: ignore[call-arg] — 토큰 인자 필수
    with pytest.raises(TokenConfigError):
        create_app(b"")
    with pytest.raises(TokenConfigError):
        load_shared_token({})
    app = create_app(token)
    assert isinstance(app, TokenGate) and isinstance(app.app, FastAPI)  # 게이트가 최외곽


def test_gate_does_not_keep_or_reveal_the_raw_token(token):
    gate = TokenGate(SpyApp(), token)
    assert token not in repr(gate).encode()
    assert all(getattr(gate, s) != token for s in TokenGate.__slots__)


# ── 물리 분리: 토큰 검증 모듈은 파싱·역직렬화·라우팅을 import하지 않음 ───────────

def test_token_module_is_physically_separated_from_body_parsing():
    tree = ast.parse(open(auth.__file__, encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "hashlib", "hmac", "logging", "os", "collections", "typing"}, imported


# ── 위조 거부: 인증 실패 감사 로그 위생 ───────────────────────────────────

def test_auth_failure_audit_contains_no_body_or_token_values(token, caplog):
    body_marker = secrets.token_hex(16).encode()
    path_marker = "/" + secrets.token_hex(8)
    presented = secrets.token_urlsafe(32).encode()
    gate = create_app(token)
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        _drive(gate, _scope([(HEADER, presented)], query=b"q=" + body_marker), body_marker)
        _drive(gate, _scope([], path=path_marker, method="BREW"), body_marker)
        _drive(gate, _scope([(HEADER, presented), (HEADER, token)]), body_marker)
    records = [r for r in caplog.records if r.name == "sentinel.audit"]
    assert [r.args[0] for r in records] == ["mismatch", "missing", "duplicate"]
    dump = "\n".join(r.getMessage() + repr(r.__dict__) for r in records)
    for secret in (token.decode(), presented.decode(), body_marker.decode(), path_marker, "BREW"):
        assert secret not in dump


def test_successful_auth_is_not_audited_as_failure(token, caplog):
    with caplog.at_level(logging.DEBUG, logger="sentinel.audit"):
        _drive(create_app(token), _scope([(HEADER, token)]), _valid_envelope())
    assert [r for r in caplog.records if r.name == "sentinel.audit"] == []


def test_uvicorn_access_log_is_disabled(monkeypatch, token):
    """요청 줄(경로·쿼리)이 uvicorn 접근 로그로 새지 않게 끈다 — 감사는 sentinel.audit만."""
    monkeypatch.setenv(TOKEN_ENV, token.decode())
    assert build_uvicorn_config(ServerConfig(port=0)).access_log is False
