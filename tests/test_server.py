"""`loopback_binding` — FastAPI 서버는 127.0.0.1에만 바인딩한다.

'위조 거부'로 증명한다: 비루프백·변형 표기 바인딩 시도는 서버를 띄우기 전에 거부되고, 기동 직후
실제 바인드 주소가 루프백이 아니면 리스너를 닫고 기동을 중단한다. 대조군으로 실제 서버를 127.0.0.1에
띄워 루프백으로 응답을 받는다(테스트 egress 가드는 루프백만 허용).
"""
from __future__ import annotations

import dataclasses
import secrets
import socket
import threading
import urllib.error
import urllib.request

import pytest
import uvicorn

import sentinel.server.serve as serve_mod
from sentinel.server.__main__ import main as cli_main
from sentinel.server.app import ANALYZE_PATH
from sentinel.server.auth import TOKEN_ENV, TOKEN_HEADER
from sentinel.server.config import BIND_HOST, LoopbackBindError, ServerConfig
from sentinel.server.serve import LoopbackOnlyServer, assert_loopback_bound, build_uvicorn_config

NON_LOOPBACK_HOSTS = [
    "0.0.0.0", "::", "", " ", "192.168.0.10", "10.0.0.1", "172.16.0.1", "8.8.8.8",
    "localhost",  # 호스트명은 해석 결과가 바뀔 수 있어 거부
    "127.0.0.2", "::1",  # (A) 표기 = 127.0.0.1만
    " 127.0.0.1", "127.0.0.1 ", "127.1", "2130706433", "0x7f000001", "127.0.0.1:80",
    None, b"127.0.0.1", 2130706433,
]


@pytest.fixture(autouse=True)
def shared_token(monkeypatch) -> str:
    """서버 기동에 필요한 공유 토큰 — 런타임 생성(하드코딩 금지, N7)."""
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv(TOKEN_ENV, token)
    return token


class _Run:
    """uvicorn 서버를 백그라운드 스레드로 띄우고, 스레드 안의 예외를 보관한다."""

    def __init__(self, server: uvicorn.Server):
        self.server, self.error = server, None
        self.thread = threading.Thread(target=self._target, daemon=True)

    def _target(self):
        try:
            self.server.run()
        except BaseException as exc:  # noqa: BLE001 — 스레드 예외를 테스트로 전달
            self.error = exc

    def start(self, timeout: float = 10.0) -> "_Run":
        self.thread.start()
        deadline = threading.Event()
        for _ in range(int(timeout / 0.05)):
            if self.server.started or not self.thread.is_alive():
                break
            deadline.wait(0.05)
        return self

    def stop(self):
        self.server.should_exit = True
        self.thread.join(10)


@pytest.fixture
def running_server():
    run = _Run(LoopbackOnlyServer(build_uvicorn_config(ServerConfig(port=0)))).start()
    assert run.server.started, run.error
    yield run
    run.stop()


def _post(port: int, path: str, body: bytes = b"", token: str | None = None) -> int:
    headers = {TOKEN_HEADER: token} if token is not None else {}
    req = urllib.request.Request(f"http://{BIND_HOST}:{port}{path}", data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


# ── 정상: 실제 기동 → 127.0.0.1 바인딩 ─────────────────────────────

def test_default_config_is_loopback():
    assert ServerConfig().host == BIND_HOST == "127.0.0.1"


def test_started_server_is_bound_to_loopback_only(running_server):
    addrs = serve_mod.bound_addresses(running_server.server)
    assert addrs and all(a[0] == BIND_HOST for a in addrs)


def test_analyze_endpoint_answers_over_loopback(running_server, shared_token):
    """대조군: 실제 서버가 루프백으로 응답한다(깨진 본문 → W1-05 스키마 게이트가 422)."""
    port = serve_mod.bound_addresses(running_server.server)[0][1]
    assert _post(port, ANALYZE_PATH, b"\x00not json{", token=shared_token) == 422


def test_docs_ui_and_openapi_are_disabled(running_server, shared_token):
    """문서 UI는 브라우저가 외부 CDN 자산을 받아 오므로 끈다(N1). 토큰을 통과해도 경로 자체가 없음."""
    port = serve_mod.bound_addresses(running_server.server)[0][1]
    for path in ("/docs", "/redoc", "/openapi.json"):
        req = urllib.request.Request(f"http://{BIND_HOST}:{port}{path}", headers={TOKEN_HEADER: shared_token})
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 404


# ── 위조 거부: 비루프백 바인딩 시도는 서버를 띄우기 전에 거부 ──────────────

@pytest.mark.parametrize("host", NON_LOOPBACK_HOSTS)
def test_rejects_non_loopback_bind_host(host):
    with pytest.raises(LoopbackBindError):
        ServerConfig(host=host)


@pytest.mark.parametrize("port", [-1, 65536, "8765", 8765.0, True, None])
def test_rejects_invalid_port(port):
    with pytest.raises(ValueError):
        ServerConfig(port=port)


def test_rejects_config_mutated_after_validation(monkeypatch):
    """frozen 우회(object.__setattr__)로 바꾼 주소도 uvicorn 설정 직전 재검증에서 거부, 서버 미기동."""
    cfg = ServerConfig(port=0)
    object.__setattr__(cfg, "host", "0.0.0.0")
    ran = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, *a, **k: ran.append(self))
    with pytest.raises(LoopbackBindError):
        serve_mod.serve(cfg)
    assert ran == []


def test_replace_cannot_produce_non_loopback_config():
    with pytest.raises(LoopbackBindError):
        dataclasses.replace(ServerConfig(), host="0.0.0.0")


def test_cli_has_no_bind_host_option():
    """설정 경로 자체가 없음: --host 옵션은 argparse가 거부(서버 미기동)."""
    with pytest.raises(SystemExit) as exc:
        cli_main(["--host", "0.0.0.0"])
    assert exc.value.code == 2


@pytest.mark.parametrize("field,value", [("host", "0.0.0.0"), ("uds", "/tmp/sentinel.sock"), ("fd", 3)])
def test_server_refuses_to_start_with_bypassed_uvicorn_config(field, value):
    """ServerConfig를 거치지 않고 uvicorn 설정을 직접 바꿔도 startup이 바인드 전에 거부."""
    config = build_uvicorn_config(ServerConfig(port=0))
    setattr(config, field, value)
    run = _Run(LoopbackOnlyServer(config)).start()
    run.thread.join(10)
    assert isinstance(run.error, LoopbackBindError)
    assert not run.server.started


# ── 위조 거부: 기동 직후 실제 바인드 주소 재확인 ───────────────────────────

@pytest.mark.parametrize("addresses", [[], [("0.0.0.0", 8765)], [("::", 8765, 0, 0)],
                                       [("127.0.0.1", 1), ("192.168.0.10", 2)], ["/tmp/sock"]])
def test_assert_loopback_bound_rejects_non_loopback_or_missing(addresses):
    with pytest.raises(LoopbackBindError):
        assert_loopback_bound(addresses)


def test_server_shuts_listener_when_actual_bind_is_not_loopback(monkeypatch):
    """바인드 결과가 비루프백으로 관측되면 기동 중단 + 리스너 닫힘(그 포트로 더는 접속 불가)."""
    seen: list[int] = []
    real = serve_mod.bound_addresses

    def forged(server):
        port = real(server)[0][1]
        seen.append(port)
        return [("0.0.0.0", port)]

    monkeypatch.setattr(serve_mod, "bound_addresses", forged)
    run = _Run(LoopbackOnlyServer(build_uvicorn_config(ServerConfig(port=0)))).start()
    run.thread.join(10)
    assert isinstance(run.error, LoopbackBindError)
    assert not run.server.started
    assert seen
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection((BIND_HOST, seen[0]), timeout=2).close()
