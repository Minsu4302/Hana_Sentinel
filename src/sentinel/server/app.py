"""FastAPI 앱 — 단일 분석 엔드포인트. 최외곽은 토큰 게이트(W1-04).

(A) §3.0 파이프라인
① 토큰 검증(W1-04, `auth.TokenGate` — 이 앱 바깥) → ② 스키마 검증(W1-05) → ③ Sanitization 재검증(W1-06)
→ ④ ExecutionResponse(W1-07). 엔드포인트는 아직 본문을 읽지 않고 501을 돌려준다.

문서 UI(/docs·/redoc)와 /openapi.json은 끈다: 문서 UI는 브라우저가 외부 CDN 자산을 받아 오므로(N1).
"""
from __future__ import annotations

from fastapi import FastAPI, Response

from sentinel.server.auth import TokenGate

ANALYZE_PATH = "/v1/analyze"


def create_api() -> FastAPI:
    """토큰 게이트 안쪽의 앱. 단독으로 서비스하지 않는다 — 항상 create_app()으로 감싼다."""
    api = FastAPI(title="Sentinel Harness", docs_url=None, redoc_url=None, openapi_url=None)

    @api.post(ANALYZE_PATH)
    async def analyze() -> Response:
        return Response(status_code=501)

    return api


def create_app(shared_token: bytes) -> TokenGate:
    """서비스용 ASGI 앱. 토큰 인자는 필수 — 인증 없는 앱을 만드는 경로를 두지 않는다."""
    return TokenGate(create_api(), shared_token, known_paths=frozenset({ANALYZE_PATH}))
