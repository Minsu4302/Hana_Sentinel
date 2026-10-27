"""마스킹 전 원본 타입 — (A) §2.7 RawTransaction(§2.2 Transaction의 마스킹 전 쌍).

이 타입은 tools/ 아래에만 있다(안전 층위 결정 — 엔진이 물리적으로 볼 수 없는 위치). 엔진(src/sentinel)은 이 이름들을
import·정의하지 않는다(`engine_tools_isolation`·`engine_no_rawtransaction`).

Transaction과의 차이(이것만 다르고 나머지 구조 제약은 같다):
- 모든 value가 평문 str — MaskedRef가 없다(MaskedRef 객체가 오면 str 자리에서 거부).
- meta.sanitization이 없다(아직 마스킹 전) — 오면 추가 필드로 거부.
- RawBody = { content_type, encoding, content }만. truncated·size_bytes·masked_spans는 마스킹 산출물이라 없다 —
  오면 거부(원본에 산출물이 섞여 들어오는 것을 막는다). 잘린 원본은 타입으로 표현할 수 없다(§2.2 절단은 마스킹 뒤).
strict + 추가 필드 금지 + 불변. 검증 오류 메시지·위치에는 입력 값이 들어갈 수 있으므로 호출자는 오류 유형만 쓴다.
"""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

RAW_SCHEMA_VERSION = "1.0"


class _Raw(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class RawParam(_Raw):
    name: str
    value: str
    location: Literal["query", "form"]


class RawHeader(_Raw):
    name: str
    value: str


class RawBody(_Raw):
    content_type: str
    encoding: Literal["utf8", "base64", "omitted"]
    content: str | None


class RawMeta(_Raw):
    transaction_id: UUID
    captured_at: AwareDatetime
    origin_ref: str


class RawRequest(_Raw):
    method: str
    scheme: Literal["http", "https"]
    host: str
    port: Annotated[int, Field(ge=0, le=65535)]
    path: str
    query_params: list[RawParam]
    headers: list[RawHeader]
    body: RawBody

    @field_validator("path")
    @classmethod
    def _no_query_string(cls, v: str) -> str:
        if "?" in v:  # (A) §2.2와 같은 구조 제약 — 쿼리는 query_params로만. 메시지에 값 없음
            raise ValueError("path에 쿼리 문자열 포함")
        return v


class RawResponse(_Raw):
    status: Annotated[int, Field(ge=100, le=599)]
    headers: list[RawHeader]
    body: RawBody
    elapsed_ms: Annotated[int, Field(ge=0)] | None


class RawTransaction(_Raw):
    meta: RawMeta
    request: RawRequest
    response: RawResponse


class RawEnvelope(_Raw):
    schema_version: Literal["1.0"]  # 모르는 버전은 거부((A) §2.7)
    transactions: Annotated[list[RawTransaction], Field(min_length=1)]
