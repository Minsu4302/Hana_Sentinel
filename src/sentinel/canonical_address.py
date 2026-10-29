"""CNA(정규 노드 주소) 정규화 — (A) §2.6 CNA, §2.4 중복 처리, §6.1 판정 단위. `canonical_address`.

엔진 안의 순수 함수 1개다(입출력·로깅 없음). 서버 중복 처리·fixture 마스커·평가기가 같은 함수를 쓴다 — tools →
엔진 import는 허용 방향이다. `sentinel.pipeline` 밖에 두므로 마스커가 써도 `masker_independence` 위반이 아니다.

정규화 규칙(결정론적, (A) §2.6 그대로):
- req_line{method|path, range?} → req_line.method | req_line.path (range 제거)
- header{side, name, occurrence, range?} → header(side, 소문자 이름, occurrence) (range 제거)
- param{location, name, occurrence, range?} → param(location, name, occurrence)
- body{json, path, range?} → body_json(side, path)
- body{text, range}:
    · 폼 본문(content-type application/x-www-form-urlencoded)에서 range가 파라미터 값 하나의 구간 안에 완전히
      들어가면 → param(form, 이름, occurrence) — 요청 쪽만(파라미터는 요청에만 있다)
    · 엄격 JSON으로 파싱되는 본문(잘리지 않음)에서 range가 문자열 값 하나의 따옴표 안에 완전히 들어가면
      → body_json(side, 그 노드의 JSON Pointer)
    · 그 밖(range 없음 포함) → body_text(side) — 승격 실패는 거친 노드로 떨어진다(FN은 평가에서 측정)
- resp_status → resp_status
range는 CNA에 포함하지 않는다(힌트). Locator가 실제로 해석되는지는 검사하지 않는다 — 그것은 출력 게이트의 일이다.
폼 파라미터 이름은 percent 디코드해 Param.name과 같은 기준으로 비교한다(값 구간은 저장 content 기준 오프셋).
"""
from __future__ import annotations

from typing import NamedTuple
from urllib.parse import unquote_plus
from uuid import UUID

from sentinel import strict_json
from sentinel.common_types import BodyLocator, HeaderLocator, ParamLocator, Range, ReqLineLocator, StatusLocator
from sentinel.schema import Body, Transaction

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


class CNA(NamedTuple):
    """(transaction_ref, node). node는 첫 원소가 종류인 튜플:
    ("req_line.method",) | ("req_line.path",) | ("header", side, 소문자 이름, occurrence)
    | ("param", location, name, occurrence) | ("body_json", side, pointer) | ("body_text", side) | ("resp_status",)
    side는 "req" | "resp"."""
    transaction_ref: UUID
    node: tuple


def _form_values(content: str) -> list[tuple[str, int, int, int]]:
    """폼 본문의 (디코드한 이름, occurrence, 값 시작, 값 끝)."""
    found: list[tuple[str, int, int, int]] = []
    seen: dict[str, int] = {}
    offset = 0
    for pair in content.split("&"):
        if "=" in pair:
            raw_name = pair.split("=", 1)[0]
            name = unquote_plus(raw_name)
            start = offset + len(raw_name) + 1
            found.append((name, seen.get(name, 0), start, offset + len(pair)))
            seen[name] = seen.get(name, 0) + 1
        offset += len(pair) + 1
    return found


def _is_form(body: Body) -> bool:
    return body.content_type.split(";", 1)[0].strip().lower() == FORM_CONTENT_TYPE


def _inside(rng: Range, start: int, end: int) -> bool:
    return start <= rng.start and rng.end <= end


def _text_node(body: Body, side: str, rng: Range | None) -> tuple:
    if rng is None or body.encoding != "utf8" or body.content is None:
        return ("body_text", side)
    if side == "req" and _is_form(body):
        for name, occurrence, start, end in _form_values(body.content):
            if _inside(rng, start, end):
                return ("param", "form", name, occurrence)
    if not body.truncated:
        try:
            strict_json.parse(body.content)
        except ValueError:
            return ("body_text", side)
        for pointer, _key, start, end in strict_json.string_value_spans(body.content):
            if _inside(rng, start + 1, end - 1):  # 따옴표 안
                return ("body_json", side, pointer)
    return ("body_text", side)


def canonical_address(tx: Transaction, locator) -> CNA:
    """Locator(§2.6) → CNA. 같은 값을 가리키는 서로 다른 Locator는 같은 CNA가 된다."""
    if isinstance(locator, ReqLineLocator):
        node: tuple = (f"req_line.{locator.part}",)
    elif isinstance(locator, HeaderLocator):
        node = ("header", "req" if locator.locus == "req_header" else "resp", locator.name.lower(), locator.occurrence)
    elif isinstance(locator, ParamLocator):
        node = ("param", locator.location, locator.name, locator.occurrence)
    elif isinstance(locator, BodyLocator):
        side = "req" if locator.locus == "req_body" else "resp"
        if locator.body.kind == "json":
            node = ("body_json", side, locator.body.path)
        else:
            body = tx.request.body if side == "req" else tx.response.body
            node = _text_node(body, side, locator.body.range)
    elif isinstance(locator, StatusLocator):
        node = ("resp_status",)
    else:
        raise TypeError("알 수 없는 Locator 변형")
    return CNA(tx.meta.transaction_id, node)


def cna_sort_key(cna: CNA) -> tuple:
    """CNA 전순서((A) §6.1, 정본): (transaction_ref 문자열, node 튜플) 사전순 — node 원소는 문자열이면 코드포인트 순,
    정수면 수 순. 같은 자리에 타입이 다르면(종류가 다른 node끼리라 실제로는 첫 원소에서 갈린다) 정수 < 문자열.
    파이썬 튜플 비교에 암묵적으로 맡기지 않는다 — CNA 구조가 바뀌면 순서가 조용히 바뀌므로 원소 타입을 명시적으로 다룬다."""
    def element(value) -> tuple:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise TypeError("CNA node 원소는 문자열 또는 정수여야 한다")
        return (0, value, "") if isinstance(value, int) else (1, 0, value)
    return (str(cna.transaction_ref), tuple(element(v) for v in cna.node))
