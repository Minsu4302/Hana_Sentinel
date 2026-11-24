"""정규 직렬화 — (A) §2.10. 생산자(fixture 마스커·Java transport)가 내보내는 Envelope의 바이트 정의.

라이브러리 직렬화(pydantic `model_dump_json` 등)를 정본으로 삼지 않는다. 이 모듈이 §2.10을 직접 구현하고,
테스트가 동결본(S v1·S v2) 재직렬화 바이트 일치와 각 규칙(이스케이프·시각·UUID·정수만·생략 없음)을 고정한다.

- UTF-8, BOM 없음, 끝 개행 없음. 공백 없음(구분자 `,` `:`).
- 객체 멤버 순서: 모델 선언 순서(= (A) 타입 정의 블록의 나열 순서). 멤버를 생략하지 않는다(None → null, 기본값도 출력).
- 문자열: `"`→`\\"`, `\\`→`\\\\`, U+0008·09·0A·0C·0D → `\\b \\t \\n \\f \\r`, 그 밖의 U+0000–001F → `\\u00XX`(소문자).
  그 밖의 문자(`/`, U+007F, 비ASCII, U+2028·2029)는 그대로. 고립 서로게이트는 거부한다(생산자가 U+FFFD로 바꿔 넣어야 한다).
- 숫자: 정수만(실수는 거부). 시각: `YYYY-MM-DDTHH:MM:SS`, 소수 초가 0이 아니면 6자리, UTC는 `Z`, 그 밖은 `±HH:MM`.
- UUID: 소문자 8-4-4-4-12.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel

_SHORT: Final = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


class CanonicalError(ValueError):
    """§2.10으로 표현할 수 없는 값(실수·고립 서로게이트·시간대 없는 시각·초 단위 오프셋 등). 값은 담지 않는다."""


def _string(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code in _SHORT:
            out.append(_SHORT[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            raise CanonicalError("lone_surrogate")
        else:
            out.append(ch)
    out.append('"')


def _datetime(value: datetime) -> str:
    offset = value.utcoffset()
    if offset is None:
        raise CanonicalError("naive_datetime")
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        text += ".%06d" % value.microsecond
    if offset == timedelta(0):
        return text + "Z"
    if offset.seconds % 60 or offset.microseconds:
        raise CanonicalError("offset_not_whole_minutes")
    sign = "+" if offset >= timedelta(0) else "-"
    minutes = abs(int(offset.total_seconds())) // 60
    return f"{text}{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def _value(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        out.append(str(v))
    elif isinstance(v, float):
        raise CanonicalError("float_not_allowed")
    elif isinstance(v, str):
        _string(v, out)
    elif isinstance(v, UUID):
        _string(str(v), out)  # str(UUID)는 소문자 8-4-4-4-12
    elif isinstance(v, datetime):
        _string(_datetime(v), out)
    elif isinstance(v, BaseModel):
        _value(v.model_dump(mode="python"), out)
    elif isinstance(v, dict):
        out.append("{")
        for i, (key, item) in enumerate(v.items()):
            if not isinstance(key, str):
                raise CanonicalError("non_string_key")
            if i:
                out.append(",")
            _string(key, out)
            out.append(":")
            _value(item, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _value(item, out)
        out.append("]")
    else:
        raise CanonicalError("unsupported_type")


def dumps(value: Any) -> bytes:
    """§2.10 바이트. 모델이면 선언 순서의 python 덤프(생략 없음)를 쓴다."""
    out: list[str] = []
    _value(value, out)
    return "".join(out).encode("utf-8")
