"""출력 스키마 게이트 — (A) §2.4 출력 검증 규칙, §3.5 C·E. LLM 초안 → AnalysisResult | OutputRejection.

검사(하나라도 실패하면 결과 전체 폐기 — 부분 수용 없음):
  ① 초안 스키마(`AnalysisDraft`: strict, 추가 필드 금지 — 서버 부여 필드 주입은 `server_field_injected`)
  ② category 폐쇄형 4종(`category_closed_enum`) — 초안 타입의 Literal
  ③ Finding마다 evidence ≥ 1(`evidence_min_one`) — 초안 타입의 최소 개수. AdvisorySignal.basis에는 적용하지
     않는다((A) 미정)
  ④ 모든 Evidence(finding·advisory)의 transaction_ref ∈ analyzed_refs(`evidence_ref_integrity`)
통과하면 서버가 부여한다(`server_assigned_status` 외): status=unverified, finding_id=UUID, corroboration=not_run,
anomaly_flags=[], review_required=true, severity_if_true=null, produced_by·analyzed_refs·analysis_meta=인자,
schema_version="1.0".

폐기는 조용히 하지 않는다: OutputRejection(닫힌 사유 코드)을 반환하고 감사에 사유 코드만 남긴다. 초안 원문·입력 값·
입력이 정한 필드명은 남기지 않는다(Pydantic 오류의 loc·msg는 분류에만 쓰고 버린다).
서버 인자는 초안 파싱 전에 검사한다. 잘못된 서버 인자는 LLM 출력 거부가 아니라 호출자 버그라 ValueError다
(analyzed_refs가 비었거나 중복 포함, produced_by가 3값 밖, analysis_meta 타입 오류 — 메시지에 값 없음).

범위((A) §3.5 각주): 검증 함수 단위(주입 테스트). 파이프라인 ④ 결선(유일 통로)은 LLM 연동 PR에서 별도 증명.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, get_args
from uuid import UUID, uuid4

from pydantic import ValidationError

from sentinel.output_schema import (
    SERVER_ASSIGNED_FIELDS, AdvisorySignal, AnalysisDraft, AnalysisMeta, AnalysisResult, Evidence, EvidenceDraft,
    Finding, ProducedBy)

audit_log = logging.getLogger("sentinel.audit")

REASON_CODES: Final = (
    "draft_unparseable",              # JSON이 아니거나 최상위가 객체가 아님
    "draft_schema_invalid",           # 그 밖의 초안 스키마 위반(누락·타입·형 변환 우회 등)
    "server_field_injected",          # 서버 부여 필드가 초안에 있음
    "unknown_field",                  # 계약 밖 필드
    "category_not_allowed",           # 폐쇄형 4종 밖 category
    "evidence_missing",               # evidence 0개인 Finding
    "evidence_ref_outside_analyzed",  # analyzed_refs 밖 transaction_ref
    "result_build_failed",            # 방어: 검사 통과 후 저장용 타입 구성 실패
)


@dataclass(frozen=True)
class OutputRejection:
    """LLM 출력 거부 — 결과 전체 폐기((A) §2.5 output_rejected). 사유 코드만 담는다."""
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.reason_codes or not set(self.reason_codes) <= set(REASON_CODES):
            raise ValueError("OutputRejection.reason_codes는 비어 있지 않은 닫힌 목록 값이어야 함")


def validate_draft(draft: str | bytes, *, analyzed_refs: Sequence[UUID], produced_by: str,
                   analysis_meta: AnalysisMeta) -> AnalysisResult | OutputRejection:
    refs = _checked_server_args(analyzed_refs, produced_by, analysis_meta)
    try:
        parsed = AnalysisDraft.model_validate_json(draft)  # ①②③
    except ValidationError as exc:
        return _reject(_classify(exc))
    outside = _refs_outside(parsed, frozenset(refs))  # ④
    if outside:
        return _reject(("evidence_ref_outside_analyzed",))
    try:
        return _assign(parsed, refs, produced_by, analysis_meta)
    except ValidationError:
        return _reject(("result_build_failed",))


def _checked_server_args(analyzed_refs: Sequence[UUID], produced_by: str, analysis_meta: AnalysisMeta) -> list[UUID]:
    # 메시지에 인자 값을 넣지 않는다.
    if isinstance(analyzed_refs, (str, bytes)) or not all(type(r) is UUID for r in analyzed_refs):
        raise ValueError("analyzed_refs는 UUID 목록이어야 함")
    # 빈 목록이면 'analyzed_refs: [] + findings: []' = 아무것도 분석하지 않았는데 깨끗함이 만들어진다((A) §2.5)
    if not analyzed_refs or len(set(analyzed_refs)) != len(analyzed_refs):
        raise ValueError("analyzed_refs는 비어 있지 않고 중복이 없어야 함")
    if type(produced_by) is not str or produced_by not in get_args(ProducedBy):
        raise ValueError("produced_by는 rule|llm|hybrid 중 하나여야 함")
    if not isinstance(analysis_meta, AnalysisMeta):
        raise ValueError("analysis_meta는 AnalysisMeta여야 함")
    return list(analyzed_refs)


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


def _refs_outside(parsed: AnalysisDraft, refs: frozenset[UUID]) -> frozenset[tuple[str, int]]:
    """analyzed_refs 밖을 참조하는 항목의 위치(목록 이름, 인덱스)."""
    bad = {("findings", i) for i, f in enumerate(parsed.findings) if any(e.transaction_ref not in refs for e in f.evidence)}
    bad |= {("advisory_signals", i) for i, a in enumerate(parsed.advisory_signals)
            if any(e.transaction_ref not in refs for e in a.basis)}
    return frozenset(bad)


def _reject(codes: tuple[str, ...]) -> OutputRejection:
    audit_log.warning("output_rejected count=%d reasons=%s", len(codes), ",".join(codes))
    return OutputRejection(codes)


def _evidence(d: EvidenceDraft) -> Evidence:
    return Evidence(transaction_ref=d.transaction_ref, locus=d.locus, pointer=d.pointer, observation=d.observation,
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
