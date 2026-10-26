"""공용 타입 — (A) §2.6 MaskedRef / FILLER / Range / BodyPointer / Locator / MaskedSpan.
입력(schema)·출력(output_schema)이 같이 쓴다. 의존 방향은 이 모듈 → 나머지 한쪽뿐이다(이 모듈은 sentinel의 다른 모듈을
import하지 않는다 — 아키텍처 테스트가 확인).

모든 모델은 strict + 추가 필드 금지 + 불변: 정수 자리(start·end·occurrence)에 bool·문자열·실수가 오면 거부하고,
Locator는 `locus`를 판별자로 하는 유니온이라 다른 변형의 필드가 섞이면 거부한다.

이 모듈은 '형태'만 검사한다. 가리킨 위치가 마스킹 후 데이터에서 실제로 해석되는지(경로 존재·occurrence 범위·
range 길이)는 `sentinel.pipeline.output_gate`가 transaction을 보고 검사한다(`evidence_pointer_resolves`).

JSON Pointer(RFC 6901): ""(루트) 또는 "/" 세그먼트의 나열. 이스케이프는 ~0·~1만. "-" 세그먼트는 어디서든 거부한다
— 그래서 실제 키가 "-"인 객체 멤버는 가리킬 수 없다(한계). 배열 인덱스의 선행 0은 배열을 만났을 때(해석 단계) 거부.

MaskedRef는 원본 생문자열을 담을 수 없는 타입이다: 값 필드가 없고(추가 필드 금지), `masked`는 리터럴 true,
`label`은 순번 라벨(`ref_` + 숫자 2~4자리, (A) §2.3 라벨 규칙) 또는 null, `kind`는 폐쇄형 enum. 따라서 마스킹됐다고
주장하는 자리에 원문을 밀반입할 경로가 타입에 없다. 같은 원본값 ⇔ 같은 라벨(양방향)은 생산자 쪽에서만 강제할 수 있다
(`label_consistency`) — 이 타입은 형식만 본다.

FILLER는 본문 안 마스킹 위치의 채움값이다. 코드 안의 정의는 여기 한 곳뿐이다((A) §2.6 값과의 일치는 테스트가 고정).
MaskedSpan의 위치가 실제로 FILLER인지 등 Body 불변식은 ③(`sentinel.pipeline.masked_span_check`)이 검증한다.
"""
from __future__ import annotations

import re
from typing import Annotated, Final, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

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


MaskKind = Literal["token", "cookie", "pii", "host"]
# 순번 라벨((A) §2.3): 해시를 잘라 쓰지 않는다. 원문·해시 원값이 들어갈 자리가 아님.
MaskLabel = Annotated[str, StringConstraints(pattern=r"^ref_[0-9]{2,4}$")]

FILLER: Final = "[MASKED]"  # (A) §2.6 — ASCII 고정 리터럴. kind·라벨 없음(마스킹 권위는 masked_spans 사이드카)


class MaskedRef(_Common):
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
    location: Literal["query", "form"]  # (A) v1.9 §2.6 — §2.2 Param.location과 같은 값
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


class MaskedSpan(_Common):
    """본문 안 마스킹 위치 사이드카((A) §2.6). range는 정확해야 한다(Evidence의 힌트 range와 의도된 비대칭)."""
    at: BodyPointer
    ref: MaskedRef
