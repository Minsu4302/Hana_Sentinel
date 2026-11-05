"""루프백 스텁 서버 — 어댑터 증명용. 127.0.0.1의 임의 포트에서 듣고 지정한 방식으로 응답한다. 추론은 하지 않는다."""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable

OK_HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = next((int(line.split(b":")[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length")), 0)
    while len(body) < length:
        body += conn.recv(65536)
    return head + b"\r\n\r\n" + body


class LlmStub:
    def __init__(self, respond: Callable[[socket.socket], None]) -> None:
        self.respond = respond
        self.requests: list[bytes] = []
        self.stop = threading.Event()
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.server.settimeout(0.05)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                try:
                    self.requests.append(_read_request(conn))
                    self.respond(conn)
                except OSError:
                    pass

    def __enter__(self) -> LlmStub:
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop.set()
        self.thread.join(timeout=5)
        self.server.close()


def ok(body: bytes) -> Callable[[socket.socket], None]:
    return lambda conn: conn.sendall(OK_HEAD % len(body) + body)


def status(line: bytes) -> Callable[[socket.socket], None]:
    return lambda conn: conn.sendall(b"HTTP/1.1 " + line + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def endless(chunk_bytes: int = 65536) -> Callable[[socket.socket], None]:
    def respond(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
        while True:
            conn.sendall(b"x" * chunk_bytes)
    return respond


def silent(seconds: float) -> Callable[[socket.socket], None]:
    return lambda conn: time.sleep(seconds)


def drip_body(interval: float, count: int) -> Callable[[socket.socket], None]:
    def respond(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
        for _ in range(count):
            conn.sendall(b"x")
            time.sleep(interval)
    return respond


def drip_head(interval: float, count: int) -> Callable[[socket.socket], None]:
    def respond(conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        for i in range(count):
            conn.sendall(b"X-Slow-%d: 1\r\n" % i)
            time.sleep(interval)
    return respond
