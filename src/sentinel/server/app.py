"""FastAPI 앱 — 단일 분석 엔드포인트. 최외곽은 토큰 게이트(W1-04).

(A) §3.0 파이프라인
① 토큰 검증(W1-04, `auth.TokenGate` — 이 앱 바깥) → ②③④는 `pipeline.entry.analyze` 한 함수다(② 스키마 검증 → ③ Sanitization
독립 재검증 → ④ 규칙 엔진 → 출력 게이트 → completed | output_rejected + manifest 스냅샷). 핸들러는 입력 거부 예외를 HTTP로
바꾸기만 하고 단계 함수를 직접 부르지 않는다. 분석은 스레드풀에서 동시 1건만 돈다 — 이벤트 루프를 막지 않으므로 LLM 처리 중에도
토큰 검증이 응답한다(`llm_concurrency`). 처리 중 + 대기가 상한을 넘으면 스레드풀에 들어가기 전에 503 busy로 끝낸다(`llm_queue_bound`).

원시 요청 본문은 MAX_REQUEST_BYTES까지만 읽는다(재검증은 본문 전체를 스캔하므로 무한 본문 차단, 413).
파이프라인 함수는 `모듈.함수`로 호출한다(스파이 우회 금지 — sentinel.pipeline 머리말 참조).
문서 UI(/docs·/redoc)와 /openapi.json은 끈다: 문서 UI는 브라우저가 외부 CDN 자산을 받아 오므로(N1).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from sentinel.manifest_snapshot import load_manifest_snapshot
from sentinel.pipeline import entry, llm_path, sanitization_check, schema_gate
from sentinel.server.auth import TokenGate
from sentinel.server.config import DEFAULT_QUEUE_LIMIT

ANALYZE_PATH = "/v1/analyze"
# 설정값(정본 결정 아님): req 64KB + resp 256KB 본문의 base64 팽창·헤더·JSON 오버헤드를 넉넉히 덮는 크기.
MAX_REQUEST_BYTES: Final = 1024 * 1024
ANALYSIS_CONCURRENCY: Final = 1

audit_log = logging.getLogger("sentinel.audit")


async def _read_capped(request: Request, limit: int) -> bytes | None:
    """limit 초과 시 즉시 중단하고 None. 초과분은 더 읽지 않는다."""
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_api(manifest_snapshot: dict[str, Any], llm_config: llm_path.LlmConfig | None = None,
               queue_limit: int = DEFAULT_QUEUE_LIMIT) -> FastAPI:
    """토큰 게이트 안쪽의 앱. 단독으로 서비스하지 않는다 — 항상 create_app()으로 감싼다."""
    api = FastAPI(title="Sentinel Harness", docs_url=None, redoc_url=None, openapi_url=None)
    one_at_a_time = asyncio.Semaphore(ANALYSIS_CONCURRENCY)
    admitted = 0

    @api.post(ANALYZE_PATH)
    async def analyze(request: Request) -> Response:
        nonlocal admitted
        raw = await _read_capped(request, MAX_REQUEST_BYTES)
        if raw is None:
            audit_log.warning("payload_too_large limit=%d", MAX_REQUEST_BYTES)
            return JSONResponse({"error": "payload_too_large"}, status_code=413)
        if admitted >= ANALYSIS_CONCURRENCY + queue_limit:
            audit_log.warning("analysis_busy reason=busy queue_limit=%d", queue_limit)
            return JSONResponse({"error": "busy"}, status_code=503)
        admitted += 1
        # 거부 응답에 오류 상세(입력 값 포함 가능)를 반사하지 않는다
        try:
            async with one_at_a_time:
                result = await run_in_threadpool(lambda: entry.analyze(raw, manifest_snapshot, llm_config))
        except schema_gate.SchemaRejected:
            return JSONResponse({"error": "schema_rejected"}, status_code=422)
        except sanitization_check.SanitizationRejected:
            return JSONResponse({"error": "sanitization_rejected"}, status_code=422)
        finally:
            admitted -= 1
        return JSONResponse(result.model_dump(mode="json"), status_code=200)

    return api


def create_app(shared_token: bytes, manifest_snapshot: dict[str, Any] | None = None, llm_config: llm_path.LlmConfig | None = None,
               queue_limit: int = DEFAULT_QUEUE_LIMIT) -> TokenGate:
    """서비스용 ASGI 앱. 토큰 인자는 필수 — 인증 없는 앱을 만드는 경로를 두지 않는다.
    manifest 스냅샷을 주지 않으면 커밋된 manifest에서 읽는다(없거나 깨졌으면 ManifestError — 기동 거부)."""
    snapshot = load_manifest_snapshot() if manifest_snapshot is None else manifest_snapshot
    return TokenGate(create_api(snapshot, llm_config, queue_limit), shared_token, known_paths=frozenset({ANALYZE_PATH}))
