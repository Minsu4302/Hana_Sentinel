"""LLM 어댑터 — 루프백 추론 서버 호출. (A) §1.3 ⓐ·ⓑ 해석, §3.1 `llm_adapter_loopback_only`·`llm_adapter_no_target_resend`·
`llm_input_from_sanitized`·`llm_adapter_bounds`.

레포에서 송신하는 유일한 파일이다. http.client만 쓴다(환경변수 프록시를 따르지 않고 리다이렉트를 따라가지 않는다). 접속 대상은
127.0.0.1 하나이고 호출자는 포트만 정한다. 대상 시스템으로 보내는 코드가 아니다 — 입력에 대상 요청을 다시 만들 필드가 없다.
입력은 ③을 통과한 값에서만 만들어진다(`llm_input`). 메시지 content는 문자열만이다(추론 서버의 원격 가져오기 차단).
API 키는 환경변수에서만 읽어 헤더로 보낸다. 인자로 받지 않으므로 호출자의 로그·예외에 닿지 않는다(N7).

아직 파이프라인에 연결되지 않았다(호출 지점 0곳). 프롬프트·출력 파싱은 2부다 — 응답 본문 바이트를 그대로 돌려준다.
오류는 사유 코드만이다. 예외·로그에 프롬프트·응답 내용을 남기지 않는다.
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Final

from sentinel.pipeline.sanitization_check import SanitizedEnvelope

COMPLETIONS_METHOD: Final = "POST"
COMPLETIONS_PATH: Final = "/v1/chat/completions"
API_KEY_ENV: Final = "LLAMA_API_KEY"
SYSTEM_PROMPT: Final = "HTTP 트랜잭션을 읽고 JSON으로만 답한다."  # 프롬프트 템플릿으로 바뀐다(결선 L3)
REASON_CODES: Final = (
    "api_key_missing",     # 환경변수에 쓸 수 있는 API 키가 없음
    "connect_failed",      # 추론 서버에 연결하지 못함
    "bad_status",          # 200이 아닌 응답(리다이렉트 포함 — 따라가지 않는다)
    "response_too_large",  # 응답 최대 바이트 초과 — 읽기 중단
    "io_timeout",          # 연결·읽기 한 번이 타임아웃
    "deadline_exceeded",   # 전체 기한 초과
    "transport_error",     # 그 밖의 전송 오류
)
READ_CHUNK_BYTES: Final = 65536
SOCKET_SHUTDOWN_BOTH: Final = 2

audit_log = logging.getLogger("sentinel.audit")


@dataclass(frozen=True)
class LlmInput:
    content: str


@dataclass(frozen=True)
class Limits:
    """설정값. 비스트리밍 응답을 기다리므로 io_timeout은 전체 기한과 같다. 모델이 바뀌면 재실측한다."""
    max_response_bytes: int = 1024 * 1024
    io_timeout_seconds: float = 120.0
    deadline_seconds: float = 120.0
    max_tokens: int = 1024


DEFAULT_LIMITS: Final = Limits()
LIMITS_DERIVED_FROM: Final = "qwen2.5-1.5b-instruct-q4_k_m@sha256:6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"


@dataclass(frozen=True)
class AdapterFailure:
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in REASON_CODES:
            raise ValueError("AdapterFailure.reason은 닫힌 목록 값이어야 함")


def llm_input(sanitized: SanitizedEnvelope) -> LlmInput:
    """③을 통과한 값의 스냅샷에서만 입력을 만든다. 구체적인 뷰·예산은 2부."""
    if not isinstance(sanitized, SanitizedEnvelope):
        raise TypeError("어댑터 입력은 ③을 통과한 값에서만 만든다")
    return LlmInput(content=sanitized.transactions_json)


def _checked_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("포트는 1~65535 정수여야 함")
    return port


def _api_key() -> str | None:
    key = os.environ.get(API_KEY_ENV, "")
    return key if key and key.isascii() and key.isprintable() and " " not in key else None  # 헤더에 넣을 수 없는 값은 오류 메시지로 새기 전에 거른다


def _request_body(payload: LlmInput, response_schema: dict, limits: Limits) -> str:
    return json.dumps({"messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": payload.content}],
                       "temperature": 0, "max_tokens": limits.max_tokens,
                       "response_format": {"type": "json_schema", "json_schema": {"name": "draft", "strict": True, "schema": response_schema}}})


def _failed(reason: str) -> AdapterFailure:
    audit_log.warning("llm_adapter_failed reason=%s", reason)
    return AdapterFailure(reason)


def _exchange(conn: http.client.HTTPConnection, body: str, key: str, limits: Limits, started: float) -> bytes | AdapterFailure:
    conn.request(COMPLETIONS_METHOD, COMPLETIONS_PATH, body=body,
                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    response = conn.getresponse()
    if response.status != 200:
        return _failed("bad_status")
    chunks: list[bytes] = []
    size = 0
    while chunk := response.read1(READ_CHUNK_BYTES):
        size += len(chunk)
        if size > limits.max_response_bytes:
            return _failed("response_too_large")
        if time.monotonic() - started > limits.deadline_seconds:
            return _failed("deadline_exceeded")
        chunks.append(chunk)
    return b"".join(chunks)


def complete(payload: LlmInput, port: int, response_schema: dict, limits: Limits = DEFAULT_LIMITS) -> bytes | AdapterFailure:
    key = _api_key()
    if key is None:
        return _failed("api_key_missing")
    conn = http.client.HTTPConnection("127.0.0.1", _checked_port(port), timeout=limits.io_timeout_seconds)
    expired = threading.Event()

    def expire() -> None:  # 소켓 타임아웃은 한 번의 읽기만 막는다 — 천천히 흘리는 서버는 전체 기한이 끊는다
        expired.set()
        if conn.sock is not None:
            try:
                conn.sock.shutdown(SOCKET_SHUTDOWN_BOTH)
            except OSError:
                pass

    timer = threading.Timer(limits.deadline_seconds, expire)
    timer.daemon = True
    started = time.monotonic()
    timer.start()
    try:
        return _exchange(conn, _request_body(payload, response_schema, limits), key, limits, started)
    except (OSError, http.client.HTTPException) as exc:
        if expired.is_set():
            return _failed("deadline_exceeded")
        if isinstance(exc, TimeoutError):
            return _failed("io_timeout")
        if isinstance(exc, ConnectionRefusedError):
            return _failed("connect_failed")
        return _failed("transport_error")
    finally:
        timer.cancel()
        conn.close()
