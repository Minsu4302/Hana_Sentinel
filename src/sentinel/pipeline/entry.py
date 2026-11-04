"""파이프라인 ②③④ 진입 — (A) §3.0. 토큰 뒤의 유일한 진입 함수다. 서버 핸들러와 평가 러너가 같은 함수를 쓴다.

①(토큰)은 전송 경계라 여기 없다. 입력 거부는 예외(SchemaRejected·SanitizationRejected)로 나가고, HTTP 변환은 호출자 몫이다.
"""
from __future__ import annotations

from typing import Any

from sentinel.pipeline import execution, sanitization_check, schema_gate
from sentinel.schema import ExecutionResponse


def analyze(raw: bytes, manifest_snapshot: dict[str, Any]) -> ExecutionResponse:
    envelope = schema_gate.parse_envelope(raw)
    sanitization_check.verify_sanitization(envelope)
    return execution.build_execution_response(envelope, manifest_snapshot)
