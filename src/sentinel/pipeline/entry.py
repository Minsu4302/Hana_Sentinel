"""파이프라인 ②③④ 진입 — (A) §3.0. 토큰 뒤의 유일한 진입 함수다. 서버 핸들러와 평가 러너가 같은 함수를 쓴다.

①(토큰)은 전송 경계라 여기 없다. 입력 거부는 예외(SchemaRejected·SanitizationRejected)로 나가고, HTTP 변환은 호출자 몫이다.
④의 규칙과 어댑터는 ③이 돌려준 같은 스냅샷을 쓴다 — ③ 뒤에 Envelope가 바뀌어도 어느 쪽에도 닿지 않는다.
llm_config가 None이면 rule_only다. 분석 시간(`elapsed_ms`)은 ③ 통과 직후부터 잰다 — LLM 호출이 그 안에 들어간다.
"""
from __future__ import annotations

import time
from typing import Any

from sentinel.pipeline import execution, llm_path, sanitization_check, schema_gate
from sentinel.schema import ExecutionResponse


def analyze(raw: bytes, manifest_snapshot: dict[str, Any], llm_config: llm_path.LlmConfig | None = None) -> ExecutionResponse:
    envelope = schema_gate.parse_envelope(raw)
    sanitized = sanitization_check.verify_sanitization(envelope)
    started = time.monotonic()
    llm_run = None if llm_config is None else llm_path.run(sanitized, llm_config)
    return execution.build_execution_response(sanitized, manifest_snapshot, llm_run, started=started)
