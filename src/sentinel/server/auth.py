"""토큰 게이트 — (A) §3.0 파이프라인 ①. 요청 최선두에서 공유 시크릿을 검증한다.

물리 분리: 이 모듈은 본문 파싱·역직렬화·FastAPI 라우팅을 import하지 않는다. 게이트는 FastAPI 앱 바깥을
감싸는 순수 ASGI 래퍼라, 검증 실패 시 하위 앱(라우팅·파서·분석·저장으로 가는 유일한 진입로)을 호출하지
않고, 요청 본문을 받는 ASGI `receive`도 호출하지 않은 채 401로 끝낸다.

- 서버 설정: 토큰은 환경변수 `SENTINEL_SHARED_TOKEN`에서만 읽는다. 미설정·빈값·형식 오류면 기동 거부
  (인증을 끄는 fallback 없음). 하드코딩 금지.
- 클라이언트 전달: 요청 헤더 `X-Sentinel-Token` 한 개. 없음·중복·불일치 → 거부.
- 비교: 양쪽 SHA-256 다이제스트를 `hmac.compare_digest`로 비교(상수시간, 길이 차이도 숨김).
- 감사: 인증 실패만 기록하며 본문·서버 토큰·제시된 헤더값은 기록하지 않는다(사유·메서드·경로 구분만).
토큰 회전·수명(`token_hardening`)은 2주차.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final

TOKEN_ENV: Final = "SENTINEL_SHARED_TOKEN"
TOKEN_HEADER: Final = "X-Sentinel-Token"
_TOKEN_HEADER_KEY: Final = TOKEN_HEADER.lower().encode("latin-1")
_KNOWN_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

audit_log = logging.getLogger("sentinel.audit")

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class TokenConfigError(RuntimeError):
    """서버 측 토큰 설정 오류 — 기동 거부. 메시지에 토큰 값을 넣지 않는다."""


def load_shared_token(environ: Mapping[str, str] | None = None) -> bytes:
    raw = (os.environ if environ is None else environ).get(TOKEN_ENV)
    if raw is None or raw == "":
        raise TokenConfigError(f"{TOKEN_ENV} 미설정·빈값 — 인증 없이 기동하지 않음")
    if not raw.isascii() or not raw.isprintable() or any(c.isspace() for c in raw):
        # 헤더로 전달 불가능한 값(비ASCII·제어문자·공백) → 어떤 요청도 통과 못 하는 잘못된 설정
        raise TokenConfigError(f"{TOKEN_ENV} 형식 오류(ASCII 인쇄 가능 문자만, 공백 불가) — 기동 거부")
    return raw.encode("ascii")


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _route_label(scope: Scope, known_paths: frozenset[str]) -> str:
    path = scope.get("path", "")
    return path if path in known_paths else "<other>"  # 임의 경로 문자열은 기록하지 않음


class TokenGate:
    """FastAPI 앱 바깥의 최외곽 ASGI 래퍼. 검증 통과 시에만 하위 앱을 호출한다."""

    __slots__ = ("app", "_digest", "_known_paths")

    def __init__(self, app: ASGIApp, shared_token: bytes, known_paths: frozenset[str] = frozenset()):
        if not isinstance(shared_token, bytes) or not shared_token:
            raise TokenConfigError("공유 토큰이 비어 있음 — 게이트 생성 거부")
        self.app = app
        self._digest = _digest(shared_token)  # 원문은 보관하지 않음
        self._known_paths = known_paths

    def __repr__(self) -> str:
        return "TokenGate(<redacted>)"

    def _check(self, scope: Scope) -> str | None:
        """None = 통과, 문자열 = 실패 사유(missing | duplicate | mismatch)."""
        values = [v for k, v in scope.get("headers", []) if k.lower() == _TOKEN_HEADER_KEY]
        if not values:
            return "missing"
        if len(values) > 1:
            return "duplicate"
        return None if hmac.compare_digest(_digest(values[0]), self._digest) else "mismatch"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(scope, receive, send)  # 서버 수명 이벤트 — 요청이 아님
            return
        reason = self._check(scope) if kind == "http" else "unsupported_scope"
        if reason is None:
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        audit_log.warning("auth_failure reason=%s scope=%s method=%s route=%s", reason, kind,
                          method if method in _KNOWN_METHODS else "<other>",
                          _route_label(scope, self._known_paths))
        if kind == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})
