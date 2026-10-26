"""출력 데이터 계약 — (A) §2.4 AnalysisResult / Finding / Evidence / AdvisorySignal.

타입 두 벌:
- **초안 타입(`*Draft`)**: LLM이 채우는 필드만 둔다. 서버가 부여하는 필드(`SERVER_ASSIGNED_FIELDS`)는 초안에
  없으므로, 하나라도 들어오면 추가 필드 금지로 거부된다. strict라 형 변환 우회(1·true·"1")도 거부한다.
- **저장용 타입**: (A) §2.4 그대로. 서버(`sentinel.pipeline.output_gate`)만 구성한다.
  타입은 지금 실제로 부여할 수 있는 값만 허용한다 — `severity_if_true`는 null만(등급 값 목록 미정의),
  `anomaly_flags`는 빈 목록만(값 목록 미정의 — `hallucinated_literal_isolation`에서 넓힌다).

`pointer`는 str만 검사하고 형식은 검증하지 않는다(pointer 문법은 5번 개정 대기).
"""
from __future__ import annotations

from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# (A) §1.1 P0 탐지 카테고리 4종(폐쇄형) — `category_closed_enum`
Category = Literal["access_control", "info_exposure", "security_misconfig", "reflected_injection_indicator"]
Locus = Literal["req_line", "req_header", "req_param", "req_body", "resp_status", "resp_header", "resp_body"]
ClaimBasis = Literal["observed", "inferred", "speculative"]
FindingStatus = Literal["unverified", "verifying", "confirmed", "false_positive", "needs_review"]
ProducedBy = Literal["rule", "llm", "hybrid"]
Corroboration = Literal["matched", "unmatched", "not_checkable", "not_run"]
NonNegative = Annotated[int, Field(ge=0)]

# 서버가 부여하는 필드 — LLM 초안에 있으면 거부(`server_assigned_status` 외). 이름만 비교하고 기록하지 않는다.
SERVER_ASSIGNED_FIELDS: Final = frozenset({
    "status", "finding_id", "produced_by", "corroboration", "anomaly_flags", "review_required",
    "severity_if_true", "analyzed_refs", "analysis_meta", "schema_version",
})


# ── LLM 초안 타입 ───────────────────────────────────────────────────

class _Draft(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class EvidenceDraft(_Draft):
    transaction_ref: UUID
    locus: Locus
    pointer: str  # 형식 미검증(5번 개정 대기)
    observation: str


class NextStep(_Draft):
    type: Literal["verification"]
    action: str
    rationale: str


class FindingDraft(_Draft):
    category: Category
    hypothesis: str
    evidence: Annotated[list[EvidenceDraft], Field(min_length=1)]  # `evidence_min_one`
    claim_basis: ClaimBasis
    limitations: list[str]
    next_steps: list[NextStep]


class AdvisorySignalDraft(_Draft):
    type: Literal["out_of_scope_advisory"]
    topic: str
    basis: list[EvidenceDraft]  # evidence ≥ 1은 Finding에만 — basis 최소 개수는 (A) 미정
    suggestion: str


class AnalysisDraft(_Draft):
    findings: list[FindingDraft]
    advisory_signals: list[AdvisorySignalDraft]


# ── 저장용 타입 (서버만 구성) ─────────────────────────────────────────

class _Stored(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Evidence(_Stored):
    transaction_ref: UUID
    locus: Locus
    pointer: str
    observation: str
    corroboration: Corroboration
    anomaly_flags: Annotated[list[str], Field(max_length=0)]  # 값 목록 미정의 → 지금은 빈 목록만
    review_required: bool


class Finding(_Stored):
    finding_id: UUID
    category: Category
    hypothesis: str
    evidence: Annotated[list[Evidence], Field(min_length=1)]
    claim_basis: ClaimBasis
    severity_if_true: None  # 항상 존재. null = 등급 매핑 미정의((A) §2.4) — 등급 값 목록이 정해지면 넓힌다
    status: FindingStatus
    produced_by: ProducedBy
    limitations: list[str]
    next_steps: list[NextStep]


class AdvisorySignal(_Stored):
    type: Literal["out_of_scope_advisory"]
    topic: str
    basis: list[Evidence]
    suggestion: str


class AnalysisMeta(_Stored):
    """호출자(서버)가 넘긴다. 게이트는 만들지 않는다. 필드 타입은 (A) 미지정 → 구현 재량."""
    model_id: str
    policy_version: str
    prompt_version: str
    ruleset_version: str
    elapsed_ms: NonNegative
    token_usage: dict[str, NonNegative] | None = None
    # 값 목록 미정의 → 4번(LLM 전략)에서 닫음. 서버가 넣는 값이라 LLM 경로가 아님.
    pipeline_mode: str
    manifest_snapshot: dict[str, Any]


class AnalysisResult(_Stored):
    schema_version: Literal["1.0"]
    analyzed_refs: list[UUID]
    findings: list[Finding]
    advisory_signals: list[AdvisorySignal]
    analysis_meta: AnalysisMeta
