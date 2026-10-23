"""서버 설정 — 바인드 주소는 127.0.0.1 고정.

(A) §3.1 `loopback_binding`. 바인드 주소를 바꾸는 설정 경로(CLI 옵션·환경변수)를 두지 않으며,
API로 다른 값을 주면 거부한다. 호스트명(`localhost` 포함)은 해석 결과가 바뀔 수 있으므로 받지 않고,
`127.0.0.1` 리터럴만 허용한다(다른 127/8 주소·`::1`·변형 표기도 거부 — (A) 표기 그대로).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

BIND_HOST: Final = "127.0.0.1"
DEFAULT_PORT: Final = 8765


class LoopbackBindError(ValueError):
    """루프백(127.0.0.1)이 아닌 바인딩 시도 — 기동 거부."""


def require_loopback_host(host: object) -> str:
    if host != BIND_HOST or type(host) is not str:
        raise LoopbackBindError(f"바인드 주소는 {BIND_HOST}만 허용 — 거부: {host!r}")
    return host


def require_port(port: object) -> int:
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError(f"포트는 0~65535 정수여야 함 — 거부: {port!r}")
    return port


@dataclass(frozen=True)
class ServerConfig:
    host: str = BIND_HOST
    port: int = DEFAULT_PORT

    def __post_init__(self) -> None:
        require_loopback_host(self.host)
        require_port(self.port)
