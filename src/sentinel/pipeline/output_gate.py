"""출력 스키마 게이트 — (A) §2.4 출력 검증 규칙, §2.6 Locator, §3.5 C·E. 생산자별 초안 → AnalysisResult | OutputRejection.

폐기 단위는 생산자 초안이다. 규칙 초안이 거부되면 OutputRejection(시스템 버그, fail-closed), LLM 초안이 거부되면 규칙 결과는
남기고 `llm_outcome`에 적는다. 두 초안을 하나로 묶으면 LLM이 실패할 때마다 규칙 결과까지 사라진다.

초안마다의 검사(하나라도 실패하면 그 초안 전체 폐기 — 부분 수용 없음):
  ① 초안 스키마(`AnalysisDraft`: strict, 추가 필드 금지 — 서버 부여 필드 주입은 `server_field_injected`,
     Locator 형태·JSON Pointer 문법 포함)
  ② category 폐쇄형 4종(`category_closed_enum`) — 초안 타입의 Literal
  ③ Finding마다 evidence ≥ 1(`evidence_min_one`) — 초안 타입의 최소 개수. AdvisorySignal.basis에는 적용하지
     않는다((A) 미정)
  ④ 모든 Evidence(finding·advisory)의 transaction_ref ∈ analyzed_refs(`evidence_ref_integrity`)
  ⑤ 모든 Evidence의 pointer(Locator)가 그 transaction(마스킹 후 데이터)에서 해석됨(`evidence_pointer_resolves`)
LLM 초안에는 Locator의 range가 없어야 한다(뷰 오프셋 ≠ 원본 오프셋).
환각 리터럴 격리((A) §2.4): 검사를 통과한 LLM 초안의 자유 문자열에서 정책 패턴 리터럴을 치환한다. ③이 데이터에 없음을 보장하므로
데이터 밖 값이다. 원문은 어디에도 남기지 않고 감사에는 패턴 이름만 남긴다. observation이면 그 evidence에, 그 밖의 문자열이면 그 항목의
evidence 전부에 `hallucinated_literal_suspected`를 붙인다. 플래그 달린 evidence는 유효 근거가 아니다 — 유효 근거가 0이면 needs_review다.
모든 검사가 끝난 뒤 중복을 처리한다(§2.4): (category, Evidence CNA 집합)이 정확히 같은 Finding은 하나로 합친다. 생산자가 다르면
규칙 문구를 남기고 produced_by=hybrid다. CNA 집합이 어떤 Finding과 정확히 같은 advisory는 버린다. 검증보다 뒤에 두는 이유: 먼저
병합하면 무효 초안이 병합으로 사라져 전체 폐기가 부분 수용이 된다.
통과하면 서버가 부여한다(`server_assigned_status` 외): status=unverified(유효 근거 0이면 needs_review), finding_id=UUID,
corroboration=not_run, anomaly_flags=위 격리 결과, review_required=true, severity_if_true=null, produced_by=생산 경로, analysis_meta=호출자가 만든 값,
analyzed_refs=transactions의 ID 목록, schema_version="1.0". 헤더 Locator의 name은 소문자로 정규화해 저장한다.

LLM 초안 거부의 감사에는 Pydantic 오류의 위치·종류 코드도 남긴다((A) §2.8). 위치 조각은 계약에 정의된 이름(필드명·판별 리터럴)과
정수 인덱스만이고 그 밖은 `<extra>`다 — 계약 밖 키는 LLM이 지어낸 문자열이다. 종류 코드는 검증 라이브러리의 고정 코드만 쓴다.
해석 실패(⑤)는 근거 위치를 locus·body kind까지만(헤더·파라미터 이름, 경로는 없음) 종류 `unresolved`로 남긴다.

폐기는 조용히 하지 않는다: OutputRejection(닫힌 사유 코드)을 반환하고 감사에 사유 코드만 남긴다. 초안 원문·입력 값·
입력이 정한 필드명·헤더 이름·경로·range 값은 남기지 않는다(Pydantic 오류의 loc·msg는 분류에만 쓰고 버린다).
서버 인자는 초안 파싱 전에 검사한다. 잘못된 서버 인자는 출력 거부가 아니라 호출자 버그라 ValueError다
(transactions가 비었거나 ID 중복, produced_by가 3값 밖, analysis_meta 타입 오류 — 메시지에 값 없음).
analyzed_refs를 따로 받지 않고 transactions에서 파생한다 — 둘이 어긋날 수 있는 경로 자체를 없앤다.

위치 해석(⑤): range 길이는 유니코드 코드포인트로 센다(UTF-16 단위 아님). range는 가리킨 값이 문자열일 때만
허용한다(MaskedRef면 금지). 본문은 utf8 + content 있음일 때만 해석되고, kind=json은 truncated가 아니고 content 전체가
표준 JSON(중복 키·NaN 없음)으로 파싱될 때만 — 경로가 정확히 1개 노드를 가리켜야 하므로 중복 키는 해석 실패다.
같은 값을 req_param과 req_body 두 방식으로 가리킬 수 있는 문제(정규 주소)는 5번 TP 판정에서 정한다(여기선 둘 다 허용).

범위((A) §3.5 각주): 검증 함수 단위(주입 테스트). ④의 현존 경로가 이 게이트를 지나는지는 `completed_via_gate`가 본다.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal, get_args, get_origin
from uuid import UUID, uuid4

from pydantic import BaseModel, ValidationError
from pydantic.fields import FieldInfo

from sentinel import strict_json
from sentinel.canonical_address import canonical_address
from sentinel.common_types import BodyLocator, HeaderLocator, ParamLocator, Range, ReqLineLocator, StatusLocator
from sentinel.output_schema import (
    SERVER_ASSIGNED_FIELDS, AdvisorySignal, AdvisorySignalDraft, AnalysisDraft, AnalysisMeta, AnalysisResult, Evidence,
    EvidenceDraft, Finding, FindingDraft, NextStep, ProducedBy, LLM_FAILURE_REASONS)
from sentinel.sanitization_policy import PATTERNS
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
    "llm_range_present",              # LLM 초안에 Locator range가 있음
    "result_build_failed",            # 방어: 검사 통과 후 저장용 타입 구성 실패
)
LLM_PATH: Final = "llm"
HYBRID: Final = "hybrid"
LITERAL_FLAG: Final = "hallucinated_literal_suspected"
LITERAL_REPLACEMENT: Final = "[hallucinated_literal_removed]"
VIEW_LIMITATION: Final = "LLM 입력 뷰가 일부만 포함"
EXTRA_PIECE: Final = "<extra>"
ERROR_KIND: Final = re.compile(r"[a-z_]{1,64}")
MAX_SITES: Final = 32


def _contract_names(root: type[BaseModel]) -> frozenset[str]:
    """초안 계약에 정의된 이름: 모든 모델의 필드명 + 판별 필드의 리터럴 값."""
    names: set[str] = set()
    discriminators: set[str] = set()
    models: list[type[BaseModel]] = []

    def walk(tp: Any) -> None:
        if isinstance(tp, type) and issubclass(tp, BaseModel):
            if tp in models:
                return
            models.append(tp)
            for name, field in tp.model_fields.items():
                names.add(name)
                if field.discriminator:
                    discriminators.add(field.discriminator)
                walk(field.annotation)
            return
        if get_origin(tp) is Annotated:
            discriminators.update(m.discriminator for m in get_args(tp)[1:] if isinstance(m, FieldInfo) and isinstance(m.discriminator, str))
        if get_origin(tp) is not Literal:
            for arg in get_args(tp):
                walk(arg)

    walk(root)
    for model in models:
        for name in discriminators & set(model.model_fields):
            names.update(v for v in get_args(model.model_fields[name].annotation) if isinstance(v, str))
    return frozenset(names)


CONTRACT_NAMES: Final = _contract_names(AnalysisDraft)
UNRESOLVED_KIND: Final = "unresolved"
# 이 게이트가 LLM 초안에 적용하는 검사(①~⑤의 해석 조건 단위). 전달 확인 표(tools/eval/schema_gap.GATE_CHECKS)가 모두 덮어야 한다
# (`llm_contract_conveyed`). 검사를 더하거나 해석 조건을 바꾸면 여기와 표를 함께 고친다.
DRAFT_CHECKS: Final = (
    "draft_schema", "category_closed", "evidence_min_one", "llm_no_range",  # ①②③ + range 금지
    "transaction_ref_in_analyzed",  # ④
    "locus_names", "status_always", "req_line_part",  # ⑤ 공통·변형
    "header_name_case_insensitive", "header_occurrence_by_name",
    "param_location_and_name_exact", "param_occurrence_by_location_and_name",
    "body_needs_content", "body_json_needs_json_content", "body_json_needs_untruncated", "body_json_one_node",
    "literal_isolation",  # 거부가 아니라 플래그
)
_RESOLUTION: Final = tuple(c for c in DRAFT_CHECKS[DRAFT_CHECKS.index("locus_names"):DRAFT_CHECKS.index("literal_isolation")])
# LLM 초안에 쓰일 수 있는 거부 사유 코드 → 그 사유를 내는 검사(DRAFT_CHECKS). 고정 테스트가 사유 코드 전부의 대응을 확인한다.
# 한계: 같은 사유 코드 아래에 새 해석 조건을 더하면(예: pointer_unresolvable의 새 조건) 기계로 못 잡는다 — DRAFT_CHECKS를 함께 고친다.
CHECKS_OF_REASON: Final = {
    "draft_unparseable": ("draft_schema",),
    "draft_schema_invalid": ("draft_schema",),
    "server_field_injected": ("draft_schema",),
    "unknown_field": ("draft_schema",),
    "category_not_allowed": ("category_closed",),
    "evidence_missing": ("evidence_min_one",),
    "evidence_ref_outside_analyzed": ("transaction_ref_in_analyzed",),
    "pointer_unresolvable": _RESOLUTION,
    "llm_range_present": ("llm_no_range",),
}
NOT_FROM_DRAFT: Final = frozenset({"result_build_failed"})  # 방어: 검사를 모두 통과한 뒤 저장용 타입 구성 실패 — 초안 조건이 아니다


def _site_piece(piece: Any) -> str:
    if isinstance(piece, int) and not isinstance(piece, bool):
        return str(piece)
    return piece if piece in CONTRACT_NAMES else EXTRA_PIECE


def _error_sites(exc: ValidationError) -> tuple[str, ...]:
    """(위치, 종류) — 값·메시지는 담지 않는다."""
    sites = set()
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        kind = err["type"] if ERROR_KIND.fullmatch(err["type"]) else EXTRA_PIECE
        sites.add(".".join(_site_piece(piece) for piece in err["loc"]) + ":" + kind)
    return tuple(sorted(sites))[:MAX_SITES]



@dataclass(frozen=True)
class OutputRejection:
    """출력 거부 — 결과 전체 폐기((A) §2.5 output_rejected). 사유 코드만 담는다."""
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.reason_codes or not set(self.reason_codes) <= set(REASON_CODES):
            raise ValueError("OutputRejection.reason_codes는 비어 있지 않은 닫힌 목록 값이어야 함")


@dataclass(frozen=True)
class LlmFailure:
    """LLM 초안을 받지 못함((A) §2.5 닫힌 목록). 내용은 담지 않는다."""
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in LLM_FAILURE_REASONS:
            raise ValueError("LlmFailure.reason은 닫힌 목록 값이어야 함")


def validate_draft(draft: str | bytes, *, transactions: Sequence[Transaction], produced_by: str,
                   analysis_meta: AnalysisMeta) -> AnalysisResult | OutputRejection:
    """생산자가 하나인 경로."""
    if not isinstance(analysis_meta, AnalysisMeta):
        raise ValueError("analysis_meta는 AnalysisMeta여야 함")
    return validate_producers(draft, None, transactions=transactions, produced_by=produced_by,
                              make_meta=lambda _llm_outcome: analysis_meta)


def validate_producers(rule_draft: str | bytes, llm: str | bytes | LlmFailure | None, *, transactions: Sequence[Transaction],
                       produced_by: str, make_meta: Callable[[str | None], AnalysisMeta],
                       llm_view_truncated: bool = False) -> AnalysisResult | OutputRejection:
    """규칙 초안과 LLM 초안을 각각 검증한 뒤 병합한다. llm이 None이면 LLM이 없는 경로다."""
    by_id = _checked_server_args(transactions, produced_by)
    rule = _checked_draft(rule_draft, by_id)
    if isinstance(rule, OutputRejection):
        return rule
    parsed, llm_outcome = _llm_result(llm, by_id, llm_view_truncated)
    findings, advisories = _combined(rule, parsed, by_id, produced_by)
    return _build(findings, advisories, tuple(by_id), make_meta(llm_outcome))


def _checked_draft(draft: str | bytes, by_id: dict[UUID, Transaction], event: str = "output_rejected") -> AnalysisDraft | OutputRejection:
    try:
        parsed = AnalysisDraft.model_validate_json(draft)  # ①②③
    except ValidationError as exc:
        return _reject(_classify(exc), event, _error_sites(exc) if event == "llm_draft_rejected" else ())
    outside = _refs_outside(parsed, frozenset(by_id))  # ④
    if outside:
        return _reject(("evidence_ref_outside_analyzed",), event)
    unresolved = _unresolvable(parsed, by_id)  # ⑤
    if unresolved:
        return _reject(("pointer_unresolvable",), event, _unresolved_sites(parsed, by_id) if event == "llm_draft_rejected" else ())
    return parsed


def _has_range(parsed: AnalysisDraft) -> bool:
    for _name, _i, e in _all_evidence(parsed):
        pointer = e.pointer.body if isinstance(e.pointer, BodyLocator) else e.pointer
        if getattr(pointer, "range", None) is not None:
            return True
    return False


class _FlaggedEvidence(EvidenceDraft):
    """격리가 표시한 근거. 초안 타입이 아니라 게이트 안의 표시다 — 입력으로 만들 수 없다."""


def _replaced(text: str, found: set[str]) -> str:
    for name, pattern in PATTERNS.items():
        text, count = pattern.subn(LITERAL_REPLACEMENT, text)
        if count:
            found.add(name)
    return text


def _isolated_evidence(evidence: list[EvidenceDraft], flag_all: bool, found: set[str]) -> list[EvidenceDraft]:
    isolated: list[EvidenceDraft] = []
    for e in evidence:
        mine: set[str] = set()
        observation = _replaced(e.observation, mine)
        found |= mine
        flagged = flag_all or bool(mine)
        isolated.append(_FlaggedEvidence(transaction_ref=e.transaction_ref, pointer=e.pointer, observation=observation) if flagged else e)
    return isolated


def _isolated_finding(f: FindingDraft, view_truncated: bool, found: set[str]) -> FindingDraft:
    mine: set[str] = set()
    hypothesis = _replaced(f.hypothesis, mine)
    limitations = [_replaced(text, mine) for text in f.limitations]
    next_steps = [NextStep(type=s.type, action=_replaced(s.action, mine), rationale=_replaced(s.rationale, mine)) for s in f.next_steps]
    found |= mine
    return FindingDraft(category=f.category, hypothesis=hypothesis, evidence=_isolated_evidence(f.evidence, bool(mine), found),
                        claim_basis=f.claim_basis, limitations=[*limitations, *((VIEW_LIMITATION,) if view_truncated else ())],
                        next_steps=next_steps)


def _isolated_advisory(a: AdvisorySignalDraft, found: set[str]) -> AdvisorySignalDraft:
    mine: set[str] = set()
    topic, suggestion = _replaced(a.topic, mine), _replaced(a.suggestion, mine)
    found |= mine
    return AdvisorySignalDraft(type=a.type, topic=topic, basis=_isolated_evidence(a.basis, bool(mine), found), suggestion=suggestion)


def _isolated(parsed: AnalysisDraft, view_truncated: bool) -> AnalysisDraft:
    found: set[str] = set()
    isolated = AnalysisDraft(findings=[_isolated_finding(f, view_truncated, found) for f in parsed.findings],
                             advisory_signals=[_isolated_advisory(a, found) for a in parsed.advisory_signals])
    if found:
        audit_log.warning("llm_literal_isolated count=%d patterns=%s", len(found), ",".join(sorted(found)))
    return isolated


def _llm_result(llm: str | bytes | LlmFailure | None, by_id: dict[UUID, Transaction],
                view_truncated: bool) -> tuple[AnalysisDraft | None, str | None]:
    if llm is None:
        return None, None
    if isinstance(llm, LlmFailure):
        return None, f"failed:{llm.reason}"
    parsed = _checked_draft(llm, by_id, "llm_draft_rejected")
    if isinstance(parsed, OutputRejection):
        return None, "rejected"
    if _has_range(parsed):
        _reject(("llm_range_present",), "llm_draft_rejected")
        return None, "rejected"
    return _isolated(parsed, view_truncated), "ok"


def _key(f: FindingDraft, by_id: dict[UUID, Transaction]) -> tuple[str, frozenset]:
    return f.category, _cna_set(f.evidence, by_id)


def _combined(rule: AnalysisDraft, llm: AnalysisDraft | None, by_id: dict[UUID, Transaction],
              produced_by: str) -> tuple[list[tuple[FindingDraft, str]], list]:
    tagged: dict[tuple[str, frozenset], tuple[FindingDraft, str]] = {}
    for f in rule.findings:
        tagged.setdefault(_key(f, by_id), (f, produced_by))
    for f in llm.findings if llm is not None else ():
        key = _key(f, by_id)
        if key not in tagged:
            tagged[key] = (f, LLM_PATH)
        elif tagged[key][1] != LLM_PATH:
            tagged[key] = (tagged[key][0], HYBRID)
    finding_sets = {cnas for _category, cnas in tagged}
    advisories = [a for draft in (rule, llm) if draft is not None for a in draft.advisory_signals
                  if _cna_set(a.basis, by_id) not in finding_sets]
    return list(tagged.values()), advisories


def _build(findings: list[tuple[FindingDraft, str]], advisories: list, refs: tuple[UUID, ...],
           meta: AnalysisMeta) -> AnalysisResult | OutputRejection:
    try:
        return _assign(findings, advisories, refs, meta)
    except ValidationError:
        return _reject(("result_build_failed",))


def _checked_server_args(transactions: Sequence[Transaction], produced_by: str) -> dict[UUID, Transaction]:
    # 메시지에 인자 값을 넣지 않는다.
    if isinstance(transactions, (str, bytes)) or not all(isinstance(t, Transaction) for t in transactions):
        raise ValueError("transactions는 Transaction 목록이어야 함")
    by_id = {t.meta.transaction_id: t for t in transactions}
    # 빈 목록이면 'analyzed_refs: [] + findings: []' = 아무것도 분석하지 않았는데 깨끗함이 만들어진다((A) §2.5)
    if not transactions or len(by_id) != len(transactions):
        raise ValueError("transactions는 비어 있지 않고 transaction_id 중복이 없어야 함")
    if type(produced_by) is not str or produced_by not in get_args(ProducedBy):
        raise ValueError("produced_by는 rule|llm|hybrid 중 하나여야 함")
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


def _unresolved_sites(parsed: AnalysisDraft, by_id: dict[UUID, Transaction]) -> tuple[str, ...]:
    """해석되지 않은 근거의 위치 — 계약 리터럴(locus·body kind)과 정수 인덱스만. 이름·경로·값은 담지 않는다((A) §2.8)."""
    found = set()
    lists = [("findings", i, "evidence", f.evidence) for i, f in enumerate(parsed.findings)]
    lists += [("advisory_signals", i, "basis", a.basis) for i, a in enumerate(parsed.advisory_signals)]
    for owner, i, field, evidence in lists:
        for j, e in enumerate(evidence):
            if _resolves(_normalized(e.pointer), by_id[e.transaction_ref]):
                continue
            pieces = [owner, i, field, j, "pointer", e.pointer.locus]
            if isinstance(e.pointer, BodyLocator):
                pieces += ["body", e.pointer.body.kind]
            found.add(".".join(_site_piece(piece) for piece in pieces) + ":" + UNRESOLVED_KIND)
    return tuple(sorted(found))[:MAX_SITES]


def _cna_set(evidence: Sequence[EvidenceDraft], by_id: dict[UUID, Transaction]) -> frozenset:
    return frozenset(canonical_address(by_id[e.transaction_ref], e.pointer) for e in evidence)


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


def resolves(locator, transaction: Transaction) -> bool:
    """Locator가 그 transaction(마스킹 후 데이터)에서 해석되는가 — 검사 ⑤의 순수 판정만(거부·사유 코드·감사 없음).
    예측 Evidence와 평가 라벨 anchor가 같은 정의를 쓴다((A) §2.6·§6.2). 헤더 이름은 비교 전에 소문자로 정규화한다."""
    return _resolves(_normalized(locator), transaction)


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

def _reject(codes: tuple[str, ...], event: str = "output_rejected", sites: tuple[str, ...] = ()) -> OutputRejection:
    if sites:
        audit_log.warning("%s count=%d reasons=%s sites=%s", event, len(codes), ",".join(codes), ",".join(sites))
    else:
        audit_log.warning("%s count=%d reasons=%s", event, len(codes), ",".join(codes))
    return OutputRejection(codes)


def _evidence(d: EvidenceDraft) -> Evidence:
    return Evidence(transaction_ref=d.transaction_ref, pointer=_normalized(d.pointer), observation=d.observation,
                    corroboration="not_run", anomaly_flags=(LITERAL_FLAG,) if isinstance(d, _FlaggedEvidence) else (),
                    review_required=True)


def _status(f: FindingDraft) -> str:
    return "needs_review" if all(isinstance(e, _FlaggedEvidence) for e in f.evidence) else "unverified"


def _assign(tagged: list[tuple[FindingDraft, str]], advisory_drafts: list, refs: tuple[UUID, ...],
            meta: AnalysisMeta) -> AnalysisResult:
    findings = tuple(Finding(finding_id=uuid4(), category=f.category, hypothesis=f.hypothesis,
                             evidence=tuple(_evidence(e) for e in f.evidence), claim_basis=f.claim_basis,
                             severity_if_true=None, status=_status(f), produced_by=source,
                             limitations=tuple(f.limitations), next_steps=tuple(f.next_steps))
                     for f, source in tagged)
    advisories = tuple(AdvisorySignal(type=a.type, topic=a.topic, basis=tuple(_evidence(e) for e in a.basis),
                                      suggestion=a.suggestion)
                       for a in advisory_drafts)
    return AnalysisResult(schema_version="1.0", analyzed_refs=refs, findings=findings, advisory_signals=advisories,
                          analysis_meta=meta)
