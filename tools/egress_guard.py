"""테스트 환경 한정 런타임 egress 가드.

(A) §3.1 `egress_runtime_block` — enforced(테스트환경 한정). pytest 세션 전체에 설치되어
외부 목적지(sentinel.egress_policy가 EXTERNAL로 분류)로의 연결·DNS 해석·UDP 송신을 실제 시스템 호출
전에 EgressBlocked로 거부하고 이벤트로 기록한다.

이벤트 구분: `probe()` 블록 안의 시도는 '의도된 테스트 프로브', 밖의 시도는 '예상치 못한 실제 egress
시도'로 기록된다. conftest가 테스트마다 후자를 검사해 있으면 그 테스트를 실패시킨다(차단만 하고
조용히 넘어가지 않음).

한계(정직 표기): 같은 프로세스의 Python `socket` 계층만 가로챈다. 하위 프로세스(git·pre-commit 등),
C 확장이 `_socket`/OS API를 직접 쓰는 경로, Windows asyncio Proactor의 IP 리터럴 연결(ConnectEx)은
잡지 못한다. 제품 런타임의 실제 차단 주체는 OS/네트워크다(`egress_enforcement_owner` = unverifiable).
"""
from __future__ import annotations

import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from sentinel.egress_policy import Destination, classify_destination


class EgressBlocked(ConnectionRefusedError):
    """테스트 egress 가드가 외부 목적지 시도를 거부함."""


@dataclass(frozen=True)
class EgressEvent:
    op: str  # connect | resolve | sendto
    host: str
    port: Any
    probe: bool  # True = probe() 안의 의도된 시도


class EgressGuard:
    def __init__(self) -> None:
        self.events: list[EgressEvent] = []
        self._probe_depth = 0
        self._originals: dict[str, Any] | None = None

    # ── 판정 ──
    def check(self, op: str, host: Any, port: Any) -> None:
        if host is None:  # getaddrinfo(None, ...) = 수동 바인드용, 송신 아님
            return
        if classify_destination(host) is Destination.LOCAL:
            return
        event = EgressEvent(op, str(host), port, probe=self._probe_depth > 0)
        self.events.append(event)
        raise EgressBlocked(f"테스트 egress 가드: 외부 목적지 {op} 차단 ({host}:{port})")

    def _check_address(self, op: str, address: Any) -> None:
        if isinstance(address, tuple) and len(address) >= 2:
            self.check(op, address[0], address[1])
        elif isinstance(address, (str, bytes)):
            return  # AF_UNIX 경로 — 같은 호스트의 IPC
        else:
            self.check(op, repr(address), None)  # 해석 불가 주소 → 외부로 취급

    @contextmanager
    def probe(self) -> Iterator[None]:
        self._probe_depth += 1
        try:
            yield
        finally:
            self._probe_depth -= 1

    def unexpected(self) -> list[EgressEvent]:
        return [e for e in self.events if not e.probe]

    def reset(self) -> None:
        self.events.clear()

    # ── 설치 ──
    @property
    def installed(self) -> bool:
        return self._originals is not None

    def install(self) -> None:
        if self._originals is not None:
            return
        guard = self
        orig = {
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "sendto": socket.socket.sendto,
            "getaddrinfo": socket.getaddrinfo,
        }

        def connect(sock, address):
            guard._check_address("connect", address)
            return orig["connect"](sock, address)

        def connect_ex(sock, address):
            guard._check_address("connect", address)
            return orig["connect_ex"](sock, address)

        def sendto(sock, data, *args):
            guard._check_address("sendto", args[-1] if args else None)
            return orig["sendto"](sock, data, *args)

        def getaddrinfo(host, port, *args, **kwargs):
            guard.check("resolve", host, port)
            return orig["getaddrinfo"](host, port, *args, **kwargs)

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.socket.sendto = sendto
        socket.getaddrinfo = getaddrinfo
        self._originals = orig

    def uninstall(self) -> None:
        if self._originals is None:
            return
        socket.socket.connect = self._originals["connect"]
        socket.socket.connect_ex = self._originals["connect_ex"]
        socket.socket.sendto = self._originals["sendto"]
        socket.getaddrinfo = self._originals["getaddrinfo"]
        self._originals = None


GUARD = EgressGuard()
