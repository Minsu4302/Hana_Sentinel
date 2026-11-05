"""파이프라인 ④ — 규칙 엔진 (+ LLM 결과) → 출력 게이트 → ExecutionResponse(completed | output_rejected). 저장 없음.

(A) §2.5: 분석 후 깨끗함 = completed + `findings: []`, 초안이 게이트에서 거부되면 output_rejected(result=null, 사유 코드는
게이트가 감사에 남긴다). 규칙 초안은 LLM 초안과 같은 게이트를 지난다 — JSON으로 직렬화해 넘기므로 서버 부여 필드 주입·
형태 위반이 같은 검사를 받는다. produced_by는 이 경로가 정한다(`RULE_PATH`) — 초안·규칙 결과에서 가져오지 않는다.

ExecutionResponse는 이 모듈의 응답 조립 한 곳에서만 만들고, 그 result는 게이트 반환값뿐이다(`completed_via_gate`).
"""
from __future__ import annotations

import copy
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sentinel.output_schema import AnalysisMeta, AnalysisResult, FindingDraft
from sentinel.pipeline import output_gate, rule_engine
from sentinel.sanitization_policy import DEFAULT_POLICY
from sentinel.schema import MODE_SKIPPED, Envelope, ExecutionResponse

SKIPPED_REASONS: Final = (MODE_SKIPPED,)
RULE_PATH: Final = "rule"


@dataclass(frozen=True)
class LlmRun:
    """LLM 호출의 결과. 초안(문자열)이거나 실패다."""
    model_id: str
    prompt_version: str
    output: str | bytes | output_gate.LlmFailure


def _draft_json(drafts: Sequence[FindingDraft]) -> str:
    return json.dumps({"findings": [d.model_dump(mode="json") for d in drafts], "advisory_signals": []})


def _analysis_meta(manifest_snapshot: dict[str, Any], started: float, llm_run: LlmRun | None,
                   llm_outcome: str | None) -> AnalysisMeta:
    return AnalysisMeta(model_id=None if llm_run is None else llm_run.model_id, policy_version=DEFAULT_POLICY.policy_version,
                        prompt_version=None if llm_run is None else llm_run.prompt_version,
                        ruleset_version=rule_engine.RULESET_VERSION, elapsed_ms=int((time.monotonic() - started) * 1000),
                        pipeline_mode="rule_only" if llm_run is None else "rule_llm", llm_outcome=llm_outcome,
                        manifest_snapshot=copy.deepcopy(manifest_snapshot))


def _skipped_reasons(llm_run: LlmRun | None, outcome: AnalysisResult | output_gate.OutputRejection) -> list[str]:
    if llm_run is None:
        return list(SKIPPED_REASONS)
    if isinstance(outcome, output_gate.OutputRejection):
        return []
    llm_outcome = outcome.analysis_meta.llm_outcome
    if llm_outcome == "rejected":
        return ["llm_rejected"]
    return [f"llm_{llm_outcome}"] if llm_outcome != "ok" else []


def build_execution_response(envelope: Envelope, manifest_snapshot: dict[str, Any],
                             llm_run: LlmRun | None = None) -> ExecutionResponse:
    started = time.monotonic()
    transactions = envelope.transactions
    draft = _draft_json([d for tx in transactions for d in rule_engine.evaluate(tx)])
    outcome = output_gate.validate_producers(
        draft, None if llm_run is None else llm_run.output, transactions=transactions, produced_by=RULE_PATH,
        make_meta=lambda llm_outcome: _analysis_meta(manifest_snapshot, started, llm_run, llm_outcome))
    rejected = isinstance(outcome, output_gate.OutputRejection)
    return ExecutionResponse(analysis_status="output_rejected" if rejected else "completed",
                             skipped_reasons=_skipped_reasons(llm_run, outcome), manifest_snapshot=copy.deepcopy(manifest_snapshot),
                             result=None if rejected else outcome)
