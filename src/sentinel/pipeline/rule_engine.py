"""규칙 엔진 — (A) §3.0 ④, §2.4. Transaction(마스킹 후) → [FindingDraft]. 순수 함수만 둔다(입출력·로깅·시각 없음).

초안에는 서버 부여 필드가 없다(타입에 자리가 없다). produced_by도 여기서 정하지 않는다 — 생산 경로는 호출자(④)가 게이트
인자로 넘긴다. 초안은 LLM 초안과 똑같이 출력 게이트(`output_gate`)를 지난다. claim_basis는 전부 observed다(관측만 말한다).

규칙 4종:
- reflected_injection_indicator: 평문 파라미터 값(MaskedRef 건너뜀)에 HTML 특수문자가 있고, 그 값 전체가 응답 본문에 정확한
  부분 문자열로 있다. 엄격 JSON 본문은 문자열 값 노드를 디코드해서 보고(키 제외), 그 밖의 utf8은 content를 본다.
  omitted·base64·잘린 본문은 보지 않는다. 여러 노드에 반사되면 cna_sort_key 순 첫 노드만, 텍스트는 첫 출현만 evidence다.
  이스케이프 목록은 없다 — 값이 변형 없이 있는가만 보므로 `&lt;`·`&#39;`·`%3C`나 제거·치환된 형태는 일치하지 않을 뿐이고,
  같은 값이 이스케이프형과 원형으로 둘 다 나오면 원형 때문에 발화한다(억제 로직이 아니다).
- info_exposure: 응답 본문에 스택 트레이스 형식이 있다. 엄격 JSON은 문자열 노드별, 그 밖의 utf8은 content.
- security_misconfig: 응답 헤더 ACAO 정확히 1개 `*` ∧ ACAC 정확히 1개 `true`(값 trim, 대소문자 구분, MaskedRef면 미발화).
  같은 이름이 중복되면 미발화한다.
- security_misconfig(출처 반사): 요청 Origin·응답 ACAO·ACAC가 각각 정확히 1개 평문이고, trim한 Origin과 ACAO가 정확히 같고
  (대소문자 구분, `null` 출처 포함) ACAO ≠ `*` ∧ ACAC = `true`. ACAO=`*` 조건으로 위 규칙과 서로 배타적이다.

JSON Pointer의 '-' 세그먼트는 Locator가 표현하지 못하므로((A) §2.6 한계) 키가 '-'인 노드는 보지 않는다.
패턴은 입력 길이에 비례해 끝나야 한다 — 반복은 줄 경계나 길이 상한 안에 둔다(256KB 응답이 그대로 들어온다).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from sentinel import strict_json
from sentinel.canonical_address import canonical_address, cna_sort_key
from sentinel.common_types import BodyLocator, HeaderLocator, JsonBodyPointer, ParamLocator, Range, TextBodyPointer
from sentinel.output_schema import EvidenceDraft, FindingDraft, NextStep
from sentinel.schema import Body, Header, Param, Transaction

RULESET_VERSION: Final = "rules-2"

REFLECTION_TRIGGER_CHARS: Final = "<>\"'"
STACK_TRACE_PATTERNS: Final = tuple(re.compile(p) for p in (
    r"(?m)^[ \t]*at [^\n]{1,512}:\d+:\d+\)?\r?$",                         # Node
    r"\bat [\w$.]{1,512}\([\w$]{1,256}\.java:\d+\)",                      # Java
    r'Exception in thread "',
    r"Traceback \(most recent call last\):",                              # Python
    r'File "[^"\n]{1,1024}", line \d+',
    r"\bat [\w.<>`]{1,512}\([^)\n]{0,512}\) in [^\n]{1,512}:line \d+",    # .NET
    r"\.php on line \d+",                                                 # PHP
    r"Stack trace:\s*#0",
))
REQUEST_ORIGIN_HEADER: Final = "origin"
CORS_ORIGIN_HEADER: Final = "access-control-allow-origin"
CORS_CREDENTIALS_HEADER: Final = "access-control-allow-credentials"

REFLECTION_LIMITATIONS: Final = (
    "렌더링 문맥을 판정하지 않는다",
    "부분 반사·변형 반사는 잡지 못한다",
    "단일 트랜잭션 관측이다",
    "JSON 문자열 이스케이프는 이스케이프로 보지 않는다(소비 측 복원 가정)",
    "경로·헤더 값의 반사는 보지 않는다",
    "omitted·base64·잘린 본문은 보지 않는다",
)
STACK_TRACE_LIMITATIONS: Final = (
    "형식 일치만 본다(목록 밖 형식은 잡지 못한다)",
    "실제 내부 경로인지 판정하지 않는다",
)
CORS_LIMITATIONS: Final = (
    "브라우저는 이 조합의 자격증명 요청을 거부한다",
    "중복 헤더는 판정하지 않는다",
)
CORS_REFLECTION_LIMITATIONS: Final = (
    "허용 목록 일치로 되돌린 정상 응답과 임의 출처 반사를 이 트랜잭션만으로는 구분할 수 없다",
    "마스킹된 Origin·ACAO는 보지 않는다",
    "중복 헤더는 판정하지 않는다",
    "단일 트랜잭션 관측",
)


def _readable(body: Body) -> bool:
    return body.encoding == "utf8" and body.content is not None


def _body_at(pointer: JsonBodyPointer | TextBodyPointer) -> BodyLocator:
    return BodyLocator(locus="resp_body", body=pointer)


def _string_nodes(tx: Transaction) -> list[tuple[str, str]] | None:
    """응답 본문이 엄격 JSON이면 (JSON Pointer, 디코드한 문자열 값) 목록을 CNA 순으로. 아니면 None."""
    body = tx.response.body
    if body.truncated:
        return None  # 잘린 content는 'content 전체'가 아니다
    try:
        strict_json.parse(body.content)
    except ValueError:
        return None
    nodes = [(pointer, strict_json.parse(body.content[start:end]))
             for pointer, _key, start, end in strict_json.string_value_spans(body.content)
             if "-" not in pointer.split("/")[1:]]
    return sorted(nodes, key=lambda n: cna_sort_key(canonical_address(tx, _body_at(JsonBodyPointer(kind="json", path=n[0])))))


def _reflected_at(value: str, nodes: list[tuple[str, str]] | None, content: str) -> BodyLocator | None:
    if nodes is not None:
        for pointer, text in nodes:
            if value in text:
                return _body_at(JsonBodyPointer(kind="json", path=pointer))
        return None
    start = content.find(value)
    if start < 0:
        return None
    return _body_at(TextBodyPointer(kind="text", range=Range(start=start, end=start + len(value))))


def _reflection_finding(tx: Transaction, param: Param, occurrence: int, reflected: BodyLocator) -> FindingDraft:
    ref = tx.meta.transaction_id
    return FindingDraft(
        category="reflected_injection_indicator",
        hypothesis=f"요청 파라미터 `{param.name}`의 값이 HTML 특수문자를 포함한 채 응답 본문에 변형 없이 나타난다 — "
                   "반사형 주입(XSS 등)이 가능할 수 있다.",
        evidence=[
            EvidenceDraft(transaction_ref=ref, observation="HTML 특수문자를 포함한 요청 파라미터 값",
                          pointer=ParamLocator(locus="req_param", location=param.location, name=param.name,
                                               occurrence=occurrence)),
            EvidenceDraft(transaction_ref=ref, pointer=reflected, observation="같은 값이 변형 없이 나타난 응답 본문 위치"),
        ],
        claim_basis="observed",
        limitations=list(REFLECTION_LIMITATIONS),
        next_steps=[NextStep(type="verification", action="사람이 Burp에서 이 응답의 렌더링 문맥을 확인한다",
                             rationale="값이 실행되는 문맥인지는 관측만으로 알 수 없다")],
    )


def reflection_rule(tx: Transaction) -> list[FindingDraft]:
    body = tx.response.body
    if not _readable(body) or body.truncated:
        return []
    nodes = _string_nodes(tx)
    findings: list[FindingDraft] = []
    seen: dict[tuple[str, str], int] = {}
    for param in tx.request.query_params:
        key = (param.location, param.name)
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        if not isinstance(param.value, str) or not set(param.value) & set(REFLECTION_TRIGGER_CHARS):
            continue
        reflected = _reflected_at(param.value, nodes, body.content)
        if reflected is not None:
            findings.append(_reflection_finding(tx, param, occurrence, reflected))
    return findings


def _first_trace(text: str) -> re.Match[str] | None:
    matches = [m for m in (p.search(text) for p in STACK_TRACE_PATTERNS) if m]
    return min(matches, key=lambda m: m.start(), default=None)


def _trace_at(tx: Transaction) -> BodyLocator | None:
    nodes = _string_nodes(tx)
    if nodes is not None:
        for pointer, text in nodes:
            if _first_trace(text):
                return _body_at(JsonBodyPointer(kind="json", path=pointer))
        return None
    match = _first_trace(tx.response.body.content)
    if match is None:
        return None
    return _body_at(TextBodyPointer(kind="text", range=Range(start=match.start(), end=match.end())))


def stack_trace_rule(tx: Transaction) -> list[FindingDraft]:
    if not _readable(tx.response.body):
        return []
    at = _trace_at(tx)
    if at is None:
        return []
    return [FindingDraft(
        category="info_exposure",
        hypothesis="응답 본문에 서버 내부 스택 트레이스 형식(호출 프레임)이 있다 — 내부 경로·구성 정보가 노출됐을 수 있다.",
        evidence=[EvidenceDraft(transaction_ref=tx.meta.transaction_id, pointer=at,
                                observation="스택 트레이스 형식과 일치하는 응답 본문 위치")],
        claim_basis="observed",
        limitations=list(STACK_TRACE_LIMITATIONS),
        next_steps=[NextStep(type="verification", action="사람이 Burp에서 이 응답의 트레이스 내용을 확인한다",
                             rationale="내부 경로·구성 정보인지는 형식만으로 알 수 없다")],
    )]


def _single_value(headers: list[Header], name: str) -> str | None:
    """그 이름의 헤더가 정확히 1개이고 평문이면 trim한 값. 아니면 None."""
    values = [h.value for h in headers if h.name.lower() == name]
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    return values[0].strip()


def cors_rule(tx: Transaction) -> list[FindingDraft]:
    headers = tx.response.headers
    if _single_value(headers, CORS_ORIGIN_HEADER) != "*" or _single_value(headers, CORS_CREDENTIALS_HEADER) != "true":
        return []
    ref = tx.meta.transaction_id
    return [FindingDraft(
        category="security_misconfig",
        hypothesis="응답이 와일드카드 출처(`*`)와 자격증명 허용을 함께 선언한다 — CORS 구성 오류일 수 있다"
                   "(같은 의도가 출처 반사 구성에서는 실제 노출로 이어질 수 있다).",
        evidence=[EvidenceDraft(transaction_ref=ref, observation="허용 출처가 와일드카드인 응답 헤더",
                                pointer=HeaderLocator(locus="resp_header", name=CORS_ORIGIN_HEADER)),
                  EvidenceDraft(transaction_ref=ref, observation="자격증명을 허용하는 응답 헤더",
                                pointer=HeaderLocator(locus="resp_header", name=CORS_CREDENTIALS_HEADER))],
        claim_basis="observed",
        limitations=list(CORS_LIMITATIONS),
        next_steps=[NextStep(type="verification", action="사람이 Burp에서 요청 출처에 따른 응답 헤더 변화를 확인한다",
                             rationale="출처 반사 구성인지는 단일 응답만으로 알 수 없다")],
    )]


def cors_reflection_rule(tx: Transaction) -> list[FindingDraft]:
    origin = _single_value(tx.request.headers, REQUEST_ORIGIN_HEADER)
    allowed = _single_value(tx.response.headers, CORS_ORIGIN_HEADER)
    credentials = _single_value(tx.response.headers, CORS_CREDENTIALS_HEADER)
    if origin is None or origin != allowed or allowed == "*" or credentials != "true":
        return []
    ref = tx.meta.transaction_id
    return [FindingDraft(
        category="security_misconfig",
        hypothesis="응답이 요청의 Origin 값을 허용 출처로 그대로 되돌리면서 자격증명 허용을 선언한다 — "
                   "다른 출처에서 자격증명이 포함된 응답을 읽을 수 있는 CORS 구성일 수 있다.",
        evidence=[EvidenceDraft(transaction_ref=ref, observation="요청의 출처 헤더",
                                pointer=HeaderLocator(locus="req_header", name=REQUEST_ORIGIN_HEADER)),
                  EvidenceDraft(transaction_ref=ref, observation="요청 출처와 같은 값의 허용 출처 응답 헤더",
                                pointer=HeaderLocator(locus="resp_header", name=CORS_ORIGIN_HEADER)),
                  EvidenceDraft(transaction_ref=ref, observation="자격증명을 허용하는 응답 헤더",
                                pointer=HeaderLocator(locus="resp_header", name=CORS_CREDENTIALS_HEADER))],
        claim_basis="observed",
        limitations=list(CORS_REFLECTION_LIMITATIONS),
        next_steps=[NextStep(type="verification", action="사람이 Burp에서 허용 목록 밖의 Origin으로 다시 보내 반사 여부를 확인한다",
                             rationale="임의 출처를 되돌리는지는 단일 응답만으로 알 수 없다(도구는 전송하지 않는다)")],
    )]


RULES: Final[tuple[Callable[[Transaction], list[FindingDraft]], ...]] = (reflection_rule, stack_trace_rule, cors_rule,
                                                                         cors_reflection_rule)


def evaluate(tx: Transaction) -> list[FindingDraft]:
    return [draft for rule in RULES for draft in rule(tx)]
