"""FastAPI 앱 — 단일 분석 엔드포인트(W1-03: 내용 없음).

엔드포인트는 아직 요청 본문을 읽지 않고 501을 돌려준다. (A) §3.0 파이프라인
① 토큰 검증(W1-04) → ② 스키마 검증(W1-05) → ③ Sanitization 재검증(W1-06) → ④ ExecutionResponse(W1-07)
가 이 순서대로 붙는다 — 여기에 미리 넣지 않는다.

문서 UI(/docs·/redoc)와 /openapi.json은 끈다: 문서 UI는 브라우저가 외부 CDN 자산을 받아 오므로(N1).
"""
from __future__ import annotations

from fastapi import FastAPI, Response

ANALYZE_PATH = "/v1/analyze"


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel Harness", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post(ANALYZE_PATH)
    async def analyze() -> Response:
        return Response(status_code=501)

    return app
