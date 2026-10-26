"""출력 스키마 게이트 — (A) §2.4 출력 검증 규칙, §2.6 Locator, §3.5 C·E. LLM 초안 → AnalysisResult | OutputRejection.

검사(하나라도 실패하면 결과 전체 폐기 — 부분 수용 없음):
  ① 초안 스키마(`AnalysisDraft`: strict, 추가 필드 금지 — 서버 부여 필드 주입은 `server_field_injected`,
     Locator 형태·JSON Pointer 문법 포함)
  ② category 폐쇄형 4종(`category_closed_enum`) — 초안 타입의 Literal
  ③ Finding마다 evidence ≥ 1(`evidence_min_one`) — 초안 타입의 최소 개수. AdvisorySignal.basis에는 적용하지
     않는다((A) 미정)
  ④ 모든 Evidence(finding·advisory)의 transaction_ref ∈ analyzed_refs(`evidence_ref_integrity`)
  ⑤ 모든 Evidence의 pointer(Locator)가 그 transaction(마스킹 후 데이터)에서 해석됨(`evidence_pointer_resolves`)
통과하면 서버가 부여한다(`server_assigned_status` 외): status=unverified, finding_id=UUID, corroboration=not_run,
anomaly_flags=[], review_required=true, severity_if_true=null, produced_by·analysis_meta=인자,
analyzed_refs=transactions의 ID 목록, schema_version="1.0". 헤더 Locator의 name은 소문자로 정규화해 저장한다.

폐기는 조용히 하지 않는다: OutputRejection(닫힌 사유 코드)을 반환하고 감사에 사유 코드만 남긴다. 초안 원문·입력 값·
입력이 정한 필드명·헤더 이름·경로·range 값은 남기지 않는다(Pydantic 오류의 loc·msg는 분류에만 쓰고 버린다).
서버 인자는 초안 파싱 전에 검사한다. 잘못된 서버 인자는 LLM 출력 거부가 아니라 호출자 버그라 ValueError다
(transactions가 비었거나 ID 중복, produced_by가 3값 밖, analysis_meta 타입 오류 — 메시지에 값 없음).
analyzed_refs를 따로 받지 않고 transactions에서 파생한다 — 둘이 어긋날 수 있는 경로 자체를 없앤다.

위치 해석(⑤): range 길이는 유니코드 코드포인트로 센다(UTF-16 단위 아님). range는 가리킨 값이 문자열일 때만
허용한다(MaskedRef면 금지). 본문은 utf8 + content 있음일 때만 해석되고, kind=json은 truncated가 아니고 content 전체가
표준 JSON(중복 키·NaN 없음)으로 파싱될 때만 — 경로가 정확히 1개 노드를 가리켜야 하므로 중복 키는 해석 실패다.
같은 값을 req_param과 req_body 두 방식으로 가리킬 수 있는 문제(정규 주소)는 5번 TP 판정에서 정한다(여기선 둘 다 허용).

범위((A) §3.5 각주): 검증 함수 단위(주입 테스트). 파이프라인 ④ 결선(유일 통로)은 LLM 연동 PR에서 별도 증명.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, get_args
from uuid import UUID, uuid4

from pydantic import ValidationError

from sentinel import strict_json
from sentinel.common_types import BodyLocator, HeaderLocator, ParamLocator, Range, ReqLineLocator, StatusLocator
from sentinel.output_schema import (
    SERVER_ASSIGNED_FIELDS, AdvisorySignal, AnalysisDraft, AnalysisMeta, AnalysisResult, Evidence, EvidenceDraft,
    Finding, ProducedBy)
from sentinel.schema import Body, Transaction

audit_log = logging.getLogger("sentinel.audit")

REASON_CODES: Final = (
    "draft_unparseable",              # JSON이 아니거나 최상위가 객체가 아님
    "draft_schema_invalid",           # 그 밖의 초안 스키마 위반(누락·타입·형 변환 우회·Locator 형태 등)
    "server_field_injected",          # 서버 부여 필드가 초안에 있음
    "unknown_field",                  # 계약 밖 필드
    "category_not_allowed",           # 폐쇄형 4종 밖 category
    "evidence_missing",               # evidence 0개인 Finding
    "evidence_ref_outside_analyzed",  # analyzed_refs 밖 transaction_ref
    "pointer_unresolvable",           # Locator가 그 transaction의 마스킹 후 데이터에서 해석되지 않음
    "result_build_failed",            # 방어: 검사 통과 후 저장용 타입 구성 실패
)



@dataclass(frozen=True)
class OutputRejection:
    """LLM 출력 거부 — 결과 전체 폐기((A) §2.5 output_rejected). 사유 코드만 담는다."""
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.reason_codes or not set(self.reason_codes) <= set(REASON_CODES):
            raise ValueError("OutputRejection.reason_codes는 비어 있지 않은 닫힌 목록 값이어야 함")


def validate_draft(draft: str | bytes, *, transactions: Sequence[Transaction], produced_by: str,
                   analysis_meta: AnalysisMeta) -> AnalysisResult | OutputRejection:
    by_id = _checked_server_args(transactions, produced_by, analysis_meta)
    try:
        parsed = AnalysisDraft.model_validate_json(draft)  # ①②③
    except ValidationError as exc:
        return _reject(_classify(exc))
    outside = _refs_outside(parsed, frozenset(by_id))  # ④
    if outside:
        return _reject(("evidence_ref_outside_analyzed",))
    unresolved = _unresolvable(parsed, by_id)  # ⑤
    if unresolved:
        return _reject(("pointer_unresolvable",))
    try:
        return _assign(parsed, list(by_id), produced_by, analysis_meta)
    except ValidationError:
        return _reject(("result_build_failed",))


def _checked_server_args(transactions: Sequence[Transaction], produced_by: str,
                         analysis_meta: AnalysisMeta) -> dict[UUID, Transaction]:
    # 메시지에 인자 값을 넣지 않는다.
    if isinstance(transactions, (str, bytes)) or not all(isinstance(t, Transaction) for t in transactions):
        raise ValueError("transactions는 Transaction 목록이어야 함")
    by_id = {t.meta.transaction_id: t for t in transactions}
    # 빈 목록이면 'analyzed_refs: [] + findings: []' = 아무것도 분석하지 않았는데 깨끗함이 만들어진다((A) §2.5)
    if not transactions or len(by_id) != len(transactions):
        raise ValueError("transactions는 비어 있지 않고 transaction_id 중복이 없어야 함")
    if type(produced_by) is not str or produced_by not in get_args(ProducedBy):
        raise ValueError("produced_by는 rule|llm|hybrid 중 하나여야 함")
    if not isinstance(analysis_meta, AnalysisMeta):
        raise ValueError("analysis_meta는 AnalysisMeta여야 함")
    return by_id


def _classify(exc: ValidationError) -> tuple[str, ...]:
    codes: set[str] = set()
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        loc, kind = err["loc"], err["type"]
        if not loc:
            codes.add("draft_unparseable")
        elif kind == "extra_forbidden":
            codes.add("server_field_injected" if loc[-1] in SERVER_ASSIGNED_FIELDS else "unknown_field")
        elif loc[-1] == "category" and kind != "missing":
            codes.add("category_not_allowed")
        elif loc[-1] == "evidence" and kind == "too_short":
            codes.add("evidence_missing")
        else:
            codes.add("draft_schema_invalid")
    return tuple(sorted(codes))


def _all_evidence(parsed: AnalysisDraft):
    """(목록 이름, 인덱스, Evidence) — finding·advisory 모두."""
    for i, f in enumerate(parsed.findings):
        for e in f.evidence:
            yield "findings", i, e
    for i, a in enumerate(parsed.advisory_signals):
        for e in a.basis:
            yield "advisory_signals", i, e


def _refs_outside(parsed: AnalysisDraft, refs: frozenset[UUID]) -> frozenset[tuple[str, int]]:
    """analyzed_refs 밖을 참조하는 항목의 위치(목록 이름, 인덱스)."""
    return frozenset((name, i) for name, i, e in _all_evidence(parsed) if e.transaction_ref not in refs)


def _unresolvable(parsed: AnalysisDraft, by_id: dict[UUID, Transaction]) -> frozenset[tuple[str, int]]:
    return frozenset((name, i) for name, i, e in _all_evidence(parsed)
                     if not _resolves(_normalized(e.pointer), by_id[e.transaction_ref]))


# ── 위치 해석 ─────────────────────────────────────────────────────

def _length(text: str) -> int:
    return len(text)  # 유니코드 코드포인트 수(Python str) — UTF-16 단위가 아님


def _range_fits(value: Any, rng: Range | None) -> bool:
    if rng is None:
        return True
    return isinstance(value, str) and rng.end <= _length(value)  # MaskedRef 등 문자열 아닌 값에 range 금지


def _normalized(pointer):
    """헤더 이름은 서버가 소문자로 정규화해 비교·저장한다((A) §2.6). 파라미터 이름은 그대로."""
    if isinstance(pointer, HeaderLocator):
        return pointer.model_copy(update={"name": pointer.name.lower()})
    return pointer


def _resolves(pointer, tx: Transaction) -> bool:
    if isinstance(pointer, StatusLocator):
        return True
    if isinstance(pointer, ReqLineLocator):
        return _range_fits(tx.request.method if pointer.part == "method" else tx.request.path, pointer.range)
    if isinstance(pointer, HeaderLocator):
        headers = tx.request.headers if pointer.locus == "req_header" else tx.response.headers
        values = [h.value for h in headers if h.name.lower() == pointer.name]
        return pointer.occurrence < len(values) and _range_fits(values[pointer.occurrence], pointer.range)
    if isinstance(pointer, ParamLocator):
        values = [p.value for p in tx.request.query_params
                  if p.location == pointer.location and p.name == pointer.name]
        return pointer.occurrence < len(values) and _range_fits(values[pointer.occurrence], pointer.range)
    if isinstance(pointer, BodyLocator):
        return _body_resolves(tx.request.body if pointer.locus == "req_body" else tx.response.body, pointer.body)
    return False


def _body_resolves(body: Body, at) -> bool:
    if body.encoding != "utf8" or body.content is None:
        return False  # omitted·base64 본문은 가리킬 수 없다
    if at.kind == "text":
        return _range_fits(body.content, at.range)
    if body.truncated:
        return False  # 잘린 content는 'content 전체'가 아니다
    try:
        doc = strict_json.parse(body.content)  # (A) §2.6 엄격 파싱 — ③과 같은 정의
    except ValueError:
        return False
    found, node = strict_json.resolve(doc, at.path)
    return found and _range_fits(node, at.range)


# ── 거부·부여 ─────────────────────────────────────────────────────

def _reject(codes: tuple[str, ...]) -> OutputRejection:
    audit_log.warning("output_rejected count=%d reasons=%s", len(codes), ",".join(codes))
    return OutputRejection(codes)


def _evidence(d: EvidenceDraft) -> Evidence:
    return Evidence(transaction_ref=d.transaction_ref, pointer=_normalized(d.pointer), observation=d.observation,
                    corroboration="not_run", anomaly_flags=[], review_required=True)


def _assign(parsed: AnalysisDraft, refs: list[UUID], produced_by: str, meta: AnalysisMeta) -> AnalysisResult:
    findings = [Finding(finding_id=uuid4(), category=f.category, hypothesis=f.hypothesis,
                        evidence=[_evidence(e) for e in f.evidence], claim_basis=f.claim_basis,
                        severity_if_true=None, status="unverified", produced_by=produced_by,
                        limitations=list(f.limitations), next_steps=list(f.next_steps))
                for f in parsed.findings]
    advisories = [AdvisorySignal(type=a.type, topic=a.topic, basis=[_evidence(e) for e in a.basis],
                                 suggestion=a.suggestion)
                  for a in parsed.advisory_signals]
    return AnalysisResult(schema_version="1.0", analyzed_refs=refs, findings=findings, advisory_signals=advisories,
                          analysis_meta=meta)
