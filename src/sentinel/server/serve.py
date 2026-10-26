"""서버 기동 — 루프백 바인딩 2중 확인.

1) 기동 전: uvicorn 설정을 만들기 직전에 바인드 주소를 다시 검증한다(설정 객체 우회 대비).
2) 기동 직후: 실제로 바인드된 소켓 주소를 읽어 127.0.0.1이 아니면 리스너를 닫고 기동을 중단한다.
외부에서 만든 소켓·fd·UNIX 소켓 주입 경로는 쓰지 않는다(바인드 주체를 이 모듈로 한정).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import uvicorn

from sentinel.audit import attach_audit_store, audit_db_path, install_egress_audit_hook
from sentinel.server.app import create_app
from sentinel.server.auth import load_shared_token
from sentinel.server.config import BIND_HOST, LoopbackBindError, ServerConfig, require_loopback_host, require_port


def build_uvicorn_config(cfg: ServerConfig, environ: Mapping[str, str] | None = None) -> uvicorn.Config:
    host = require_loopback_host(cfg.host)
    port = require_port(cfg.port)
    token = load_shared_token(environ)  # 미설정·빈값 → TokenConfigError, uvicorn 미생성(기동 거부)
    # access_log 끔: 요청 줄(경로·쿼리)을 기록하지 않는다 — 감사는 sentinel.audit만.
    return uvicorn.Config(create_app(token), host=host, port=port, proxy_headers=False,
                          server_header=False, access_log=False, log_level="warning")


def bound_addresses(server: uvicorn.Server) -> list[Any]:
    return [sock.getsockname() for srv in server.servers for sock in srv.sockets]


def assert_loopback_bound(addresses: list[Any]) -> None:
    if not addresses:
        raise LoopbackBindError("바인드된 리스너 없음 — 루프백 바인딩을 확인할 수 없음")
    for addr in addresses:
        host = addr[0] if isinstance(addr, tuple) else addr
        if host != BIND_HOST:
            raise LoopbackBindError(f"실제 바인드 주소가 {BIND_HOST}가 아님: {addr!r}")


class LoopbackOnlyServer(uvicorn.Server):
    async def startup(self, sockets: list[Any] | None = None) -> None:
        if sockets is not None or self.config.fd is not None or self.config.uds is not None:
            raise LoopbackBindError("소켓·fd·UNIX 소켓 주입 경로는 허용하지 않음(host/port 바인드만)")
        require_loopback_host(self.config.host)
        await super().startup(sockets=None)
        if self.should_exit:
            return  # uvicorn 자체 바인드 실패
        try:
            assert_loopback_bound(bound_addresses(self))
        except LoopbackBindError:
            self.started = False
            self.should_exit = True
            for srv in self.servers:
                srv.close()
                await srv.wait_closed()
            raise


def serve(cfg: ServerConfig) -> None:
    config = build_uvicorn_config(cfg)  # 토큰·manifest·바인드 주소 검증이 모두 끝난 뒤에만
    attach_audit_store(audit_db_path())  # 감사 → SQLite (기록 실패 시 fail-closed는 수용 요청 감사(B-6) 범위 확정 시)
    install_egress_audit_hook()  # egress 시도 관측·기록(차단 아님)
    LoopbackOnlyServer(config).run()
