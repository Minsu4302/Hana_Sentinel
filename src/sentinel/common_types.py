"""공용 타입 — (A) §2.6 Range / BodyPointer / Locator. 입력(schema)·출력(output_schema)이 같이 쓴다.

모든 모델은 strict + 추가 필드 금지 + 불변: 정수 자리(start·end·occurrence)에 bool·문자열·실수가 오면 거부하고,
Locator는 `locus`를 판별자로 하는 유니온이라 다른 변형의 필드가 섞이면 거부한다.

이 모듈은 '형태'만 검사한다. 가리킨 위치가 마스킹 후 데이터에서 실제로 해석되는지(경로 존재·occurrence 범위·
range 길이)는 `sentinel.pipeline.output_gate`가 transaction을 보고 검사한다(`evidence_pointer_resolves`).

JSON Pointer(RFC 6901): ""(루트) 또는 "/" 세그먼트의 나열. 이스케이프는 ~0·~1만. "-" 세그먼트는 어디서든 거부한다
— 그래서 실제 키가 "-"인 객체 멤버는 가리킬 수 없다(한계). 배열 인덱스의 선행 0은 배열을 만났을 때(해석 단계) 거부.
MaskedRef 이동·FILLER·MaskedSpan은 ζ2.
"""
from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

NonNegative = Annotated[int, Field(ge=0)]

_POINTER_RE: Final = re.compile(r"^(/([^~/]|~[01])*)*$")


def _check_json_pointer(value: str) -> str:
    if not _POINTER_RE.match(value):
        raise ValueError("RFC 6901 JSON Pointer 형식이 아님(이스케이프는 ~0·~1만)")
    if "-" in value.split("/")[1:]:
        raise ValueError("JSON Pointer의 '-' 세그먼트는 금지")
    return value


JsonPointer = Annotated[str, AfterValidator(_check_json_pointer)]


class _Common(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Range(_Common):
    """유니코드 코드포인트, 반열림 [start, end). 대상 = 가리킨 '저장 값' 문자열."""
    start: NonNegative
    end: int

    @model_validator(mode="after")
    def _end_after_start(self) -> Self:
        if self.end <= self.start:
            raise ValueError("Range.end는 start보다 커야 함")
        return self


class JsonBodyPointer(_Common):
    kind: Literal["json"]
    path: JsonPointer
    range: Range | None = None


class TextBodyPointer(_Common):
    kind: Literal["text"]
    range: Range | None = None


BodyPointer = Annotated[JsonBodyPointer | TextBodyPointer, Field(discriminator="kind")]


class ReqLineLocator(_Common):
    locus: Literal["req_line"]
    part: Literal["method", "path"]
    range: Range | None = None


class HeaderLocator(_Common):
    locus: Literal["req_header", "resp_header"]
    name: str  # 서버가 소문자로 정규화해 비교·저장한다(output_gate)
    occurrence: NonNegative = 0
    range: Range | None = None


class ParamLocator(_Common):
    locus: Literal["req_param"]
    location: Literal["query", "form", "json", "path"]
    name: str  # 대소문자 유지
    occurrence: NonNegative = 0
    range: Range | None = None


class BodyLocator(_Common):
    locus: Literal["req_body", "resp_body"]
    body: BodyPointer


class StatusLocator(_Common):
    locus: Literal["resp_status"]


Locator = Annotated[ReqLineLocator | HeaderLocator | ParamLocator | BodyLocator | StatusLocator,
                    Field(discriminator="locus")]
