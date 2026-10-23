"""입력 데이터 계약 v0.1 — (A) §2.1 Envelope / §2.2 Transaction / §2.3 SanitizationReceipt·MaskedRef.

구조 검증만 한다(파이프라인 ②). sanitization *값* 재검증(생문자열 잔존 재스캔)은 W1-06.
모든 모델은 strict + 추가 필드 금지 + 불변: 형 변환으로 우회하는 입력("1"→1, "true"→True 등)과
계약 밖 필드는 거부한다.

MaskedRef는 원본 생문자열을 담을 수 없는 타입이다: 값 필드가 없고(추가 필드 금지), `masked`는 리터럴 true,
`label`은 짧은 가명 라벨 형식(`principal_01`)만, `kind`는 폐쇄형 enum. 따라서 마스킹됐다고 주장하는
자리(MaskedRef 객체)에 원문을 밀반입할 경로가 타입에 없다. 단 (A) §2.2에서 Param/Header 값은
`str | MaskedRef`이므로 평문 문자열 자체는 계약상 허용된다 — 그 평문에 비밀값이 남았는지는 W1-06이 본다.
"""
from __future__ import annotations

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

MaskKind = Literal["token", "cookie", "pii", "host"]
# 가명 라벨: 소문자 접두 + 밑줄 + 두 자리 이상 일련번호(예: principal_01). 원문·해시 원값이 들어갈 자리가 아님.
MaskLabel = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{0,23}_[0-9]{2,4}$")]
Port = Annotated[int, Field(ge=0, le=65535)]
NonNegative = Annotated[int, Field(ge=0)]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class MaskedRef(_Strict):
    # Literal[True]는 strict에서도 1 == True로 정수 1을 통과시킨다 → 엄격 bool + 값 검사로 고정.
    masked: bool
    label: MaskLabel | None
    kind: MaskKind

    @field_validator("masked")
    @classmethod
    def _must_be_true(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("MaskedRef.masked는 true여야 함")
        return v


class SanitizationReceipt(_Strict):
    applied: bool
    failed: bool
    policy_version: str
    redacted_count: NonNegative
    redacted_kinds: list[MaskKind]  # 종류만(값 없음, 감사용)


class Param(_Strict):
    name: str
    value: str | MaskedRef
    location: Literal["query", "form", "json", "path"]


class Header(_Strict):
    name: str
    value: str | MaskedRef


class Body(_Strict):
    content_type: str
    size_bytes: NonNegative  # 원본 크기
    truncated: bool
    encoding: Literal["utf8", "base64", "omitted"]
    content: str | None


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
    path: str
    query_params: list[Param]
    headers: list[Header]
    body: Body


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
