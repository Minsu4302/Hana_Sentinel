"""파이프라인 ④ — 1주차: 분석 없음 → ExecutionResponse(analysis_status="not_implemented").

(A) §2.5: `findings: []`는 "분석 후 깨끗함"으로 읽힐 수 있으므로 1주차 응답에는 findings가 아예 없다.
"분석 안 함 ≠ 분석 후 취약점 없음." 규칙엔진·LLM·출력 스키마 검증·저장은 이후 주차.
"""
from __future__ import annotations

import copy
from typing import Any, Final

from sentinel.schema import Envelope, ExecutionResponse

SKIPPED_REASONS: Final = ("rule_engine_not_implemented", "llm_analysis_not_implemented")


def build_execution_response(envelope: Envelope, manifest_snapshot: dict[str, Any]) -> ExecutionResponse:
    del envelope  # 1주차: 입력을 분석하지 않는다(검증만 통과한 상태)
    return ExecutionResponse(analysis_status="not_implemented", skipped_reasons=list(SKIPPED_REASONS),
                             manifest_snapshot=copy.deepcopy(manifest_snapshot))
