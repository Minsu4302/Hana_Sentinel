"""입력 데이터 계약 v0.1 — (A) §2.1 Envelope / §2.2 Transaction / §2.3 SanitizationReceipt. MaskedRef·MaskedSpan은 §2.6
공용 타입(`sentinel.common_types`).

구조 검증만 한다(파이프라인 ②). sanitization *값* 재검증(생문자열 잔존 재스캔)은 W1-06.
모든 모델은 strict + 추가 필드 금지 + 불변: 형 변환으로 우회하는 입력("1"→1, "true"→True 등)과
계약 밖 필드는 거부한다.

MaskedRef 자리에 원문을 밀반입할 경로는 타입에 없다(`common_types` 참조). 단 (A) §2.2에서 Param/Header 값은
`str | MaskedRef`이므로 평문 문자열 자체는 계약상 허용된다 — 그 평문에 비밀값이 남았는지는 ③(W1-06)이 본다.
Body.masked_spans는 형태만 여기서 보고, Body 불변식 1~6은 ③(`masked_span_check`)이 본다.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.common_types import MaskedRef, MaskedSpan

Port = Annotated[int, Field(ge=0, le=65535)]
NonNegative = Annotated[int, Field(ge=0)]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class RedactedKinds(_Strict):
    """(A) v1.4 §2.3 — 종류별 개수 맵(값 없음, 감사용). 네 종류 모두 필수."""
    token: NonNegative
    cookie: NonNegative
    pii: NonNegative
    host: NonNegative


class SanitizationReceipt(_Strict):
    """요청자가 쓰는 '주장'. 파이프라인 ③은 이 값을 믿지 않고 데이터를 재검증한다((A) §2.3 신뢰 경계)."""
    applied: bool
    failed: bool
    policy_version: str
    redacted_count: NonNegative
    redacted_kinds: RedactedKinds


class Param(_Strict):
    name: str
    value: str | MaskedRef
    location: Literal["query", "form"]  # (A) v1.9 §2.2: json·path 제거(본문 값은 BodyPointer, 경로 파라미터는 Java가 판별 불가)


class Header(_Strict):
    name: str
    value: str | MaskedRef


class Body(_Strict):
    content_type: str
    size_bytes: NonNegative  # 원본 크기
    truncated: bool
    encoding: Literal["utf8", "base64", "omitted"]
    content: str | None
    masked_spans: list[MaskedSpan] = []  # (A) v1.7 §2.2 가산 — 불변식 1~6은 ③


class Meta(_Strict):
    transaction_id: UUID
    captured_at: AwareDatetime  # ISO8601 + 시간대 필수
    origin_ref: str  # Burp 내부 id(실호스트 아님)
    sanitization: SanitizationReceipt


class Request(_Strict):
    method: str
    scheme: Literal["http", "https"]
    host: str
    port: Port
    path: str  # 쿼리 미포함 — 쿼리는 query_params(location=query)로만((A) §2.2)
    query_params: list[Param]
    headers: list[Header]
    body: Body

    @field_validator("path")
    @classmethod
    def _no_query_string(cls, v: str) -> str:
        # 디코딩 전 raw 문자열에서 리터럴 '?'만 본다. 인코딩된 '%3F'는 경로 세그먼트의 정상 일부라 통과.
        # 'Java가 쿼리를 분리했다'는 계약을 믿지 않고 ②에서 재검증한다(path_no_query_string). 메시지에 값 없음.
        if "?" in v:
            raise ValueError("request.path에 쿼리 문자열('?') 포함 — 쿼리는 query_params로만")
        return v


class Response(_Strict):
    status: Annotated[int, Field(ge=100, le=599)]
    headers: list[Header]
    body: Body
    elapsed_ms: NonNegative | None  # ★ 시간기반 SQLi 탐지에 사용 금지(제외 카테고리)


class Transaction(_Strict):
    meta: Meta
    request: Request
    response: Response


class Envelope(_Strict):
    schema_version: Literal["1.0"]
    analysis_type: Literal["single"]  # P1에서 "diff" 추가(가산적)
    transactions: list[Transaction]

    @model_validator(mode="after")
    def _single_means_exactly_one(self) -> Self:
        if self.analysis_type == "single" and len(self.transactions) != 1:
            raise ValueError(f"analysis_type=single이면 transactions는 정확히 1개 — {len(self.transactions)}개 거부")
        return self


# ── 출력: (A) §2.5 ExecutionResponse — 분석 실행 상태(AnalysisResult와 구분) ──────────────

class ExecutionResponse(_Strict):
    """1주차 골격은 이 타입만 반환한다. findings 필드가 없다 — "분석 안 함 ≠ 분석 후 취약점 없음"."""
    analysis_status: Literal["not_implemented"]
    skipped_reasons: Annotated[list[str], Field(min_length=1)]
    manifest_snapshot: dict[str, Any]
