"""서버 기동 — 루프백 바인딩 2중 확인.

1) 기동 전: uvicorn 설정을 만들기 직전에 바인드 주소를 다시 검증한다(설정 객체 우회 대비).
2) 기동 직후: 실제로 바인드된 소켓 주소를 읽어 127.0.0.1이 아니면 리스너를 닫고 기동을 중단한다.
외부에서 만든 소켓·fd·UNIX 소켓 주입 경로는 쓰지 않는다(바인드 주체를 이 모듈로 한정).
"""
from __future__ import annotations

from typing import Any

import uvicorn

from sentinel.server.app import create_app
from sentinel.server.config import BIND_HOST, LoopbackBindError, ServerConfig, require_loopback_host, require_port


def build_uvicorn_config(cfg: ServerConfig) -> uvicorn.Config:
    host = require_loopback_host(cfg.host)
    port = require_port(cfg.port)
    return uvicorn.Config(create_app(), host=host, port=port, proxy_headers=False,
                          server_header=False, log_level="warning")


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
    LoopbackOnlyServer(build_uvicorn_config(cfg)).run()
