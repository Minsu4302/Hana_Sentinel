"""출력 데이터 계약 — (A) §2.4 AnalysisResult / Finding / Evidence / AdvisorySignal.

타입 두 벌:
- **초안 타입(`*Draft`)**: LLM이 채우는 필드만 둔다. 서버가 부여하는 필드(`SERVER_ASSIGNED_FIELDS`)는 초안에
  없으므로, 하나라도 들어오면 추가 필드 금지로 거부된다. strict라 형 변환 우회(1·true·"1")도 거부한다.
- **저장용 타입**: (A) §2.4 그대로. 서버(`sentinel.pipeline.output_gate`)만 구성한다.
  타입은 지금 실제로 부여할 수 있는 값만 허용한다 — `severity_if_true`는 null만(등급 값 목록 미정의),
  `anomaly_flags`는 빈 목록만(값 목록 미정의 — `hallucinated_literal_isolation`에서 넓힌다).

`pointer`는 (A) §2.6 Locator(`sentinel.common_types`) — 형태는 타입이, 마스킹 후 데이터에서의 해석은 게이트가 검사한다.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Any, Final, Literal, Self
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, PlainSerializer, model_validator

from sentinel.common_types import Locator

# (A) §1.1 P0 탐지 카테고리 4종(폐쇄형) — `category_closed_enum`
Category = Literal["access_control", "info_exposure", "security_misconfig", "reflected_injection_indicator"]
ClaimBasis = Literal["observed", "inferred", "speculative"]
FindingStatus = Literal["unverified", "verifying", "confirmed", "false_positive", "needs_review"]
ProducedBy = Literal["rule", "llm", "hybrid"]
Corroboration = Literal["matched", "unmatched", "not_checkable", "not_run"]
PipelineMode = Literal["rule_only", "rule_llm"]
NonNegative = Annotated[int, Field(ge=0)]
ProducerVersion = Annotated[str, Field(min_length=1)]

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
    pointer: Locator  # locus는 Locator 안의 판별자(별도 locus 필드 없음)
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
# 불변이다 — frozen + 목록 필드는 tuple, 맵 필드는 깊은 읽기 전용 사본(JSON 형태는 배열·객체 그대로). 게이트 통과 뒤 내용을
# 바꾸는 경로를 두지 않는다.

def _deep_frozen(value: Any) -> Any:
    """JSON 값의 읽기 전용 사본 — 객체는 MappingProxyType, 배열은 tuple. 원본과 공유하지 않는다. 그 밖의 타입은 거부."""
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_frozen(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_frozen(v) for v in value)
    if value is None or isinstance(value, (str, int, float)):
        return value
    raise ValueError("JSON 값이 아님")


def _thawed(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thawed(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thawed(v) for v in value]
    return value


_FrozenMap = (AfterValidator(_deep_frozen), PlainSerializer(_thawed))


class _Stored(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Evidence(_Stored):
    transaction_ref: UUID
    pointer: Locator
    observation: str
    corroboration: Corroboration
    anomaly_flags: Annotated[tuple[str, ...], Field(max_length=0)]  # 값 목록 미정의 → 지금은 빈 목록만
    review_required: bool


class Finding(_Stored):
    finding_id: UUID
    category: Category
    hypothesis: str
    evidence: Annotated[tuple[Evidence, ...], Field(min_length=1)]
    claim_basis: ClaimBasis
    severity_if_true: None  # 항상 존재. null = 등급 매핑 미정의((A) §2.4) — 등급 값 목록이 정해지면 넓힌다
    status: FindingStatus
    produced_by: ProducedBy
    limitations: tuple[str, ...]
    next_steps: tuple[NextStep, ...]


class AdvisorySignal(_Stored):
    type: Literal["out_of_scope_advisory"]
    topic: str
    basis: tuple[Evidence, ...]
    suggestion: str


def producer_versions_consistent(pipeline_mode: str, model_id: str | None, prompt_version: str | None) -> bool:
    """(A) §2.4: rule_only면 model_id·prompt_version은 null, 그 외에는 필수 — LLM이 없는 경로에 값을 지어내지 않는다."""
    if pipeline_mode == "rule_only":
        return model_id is None and prompt_version is None
    return model_id is not None and prompt_version is not None


class AnalysisMeta(_Stored):
    """호출자(서버)가 넘긴다. 게이트는 만들지 않는다. 필드 타입은 (A) 미지정 → 구현 재량."""
    model_id: ProducerVersion | None
    policy_version: str
    prompt_version: ProducerVersion | None
    ruleset_version: str
    elapsed_ms: NonNegative
    token_usage: Annotated[dict[str, NonNegative], *_FrozenMap] | None = None
    pipeline_mode: PipelineMode
    manifest_snapshot: Annotated[dict[str, Any], *_FrozenMap]

    @model_validator(mode="after")
    def _versions_match_mode(self) -> Self:
        if not producer_versions_consistent(self.pipeline_mode, self.model_id, self.prompt_version):
            raise ValueError("rule_only ⇔ model_id·prompt_version null")
        return self


class AnalysisResult(_Stored):
    schema_version: Literal["1.0"]
    analyzed_refs: tuple[UUID, ...]
    findings: tuple[Finding, ...]
    advisory_signals: tuple[AdvisorySignal, ...]
    analysis_meta: AnalysisMeta
