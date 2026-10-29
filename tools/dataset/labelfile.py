"""평가 라벨 파일 — (A) §6.2 LabelFile·Label, 라벨 무결성. 평가기(채점)는 아직 없다 — 하네스에서.

라벨 무결성(동결 전에 막는다 — 예측 Evidence 무결성과 같은 검증을 라벨에):
- (가) anchor는 Locator(§2.6) 타입으로만 읽힌다(스키마가 보장). `canonical_address`가 CNA를 돌려준다.
- (나) 실질 방어: anchor가 transaction_ref가 가리키는 마스킹된 Envelope에서 실제로 해석된다 — 출력 게이트의 공개 판정
  `output_gate.resolves`를 그대로 쓴다(예측 evidence와 라벨 anchor가 같은 정의). 없는 위치를 가리키면 그 라벨은 거부.
라벨링 지침(§6.1 — 거친 노드 body_text·req_line.path를 더 세밀한 노드가 있을 때 anchor로 쓰지 않음)은 라벨러가 지키는
지침이며 여기서 기계 강제하지 않는다.
"""
from __future__ import annotations

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from sentinel.canonical_address import canonical_address
from sentinel.common_types import Locator
from sentinel.output_schema import Category
from sentinel.pipeline import output_gate
from sentinel.schema import Transaction

LABELFILE_SCHEMA_VERSION = "1.0"
MaskingMode = Literal["strict_redaction", "relation_preserving"]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Label(_Strict):
    transaction_ref: UUID
    label_status: Literal["labeled_positive", "verified_clean", "unlabeled"]
    categories: list[Category]
    anchors: list[Locator]
    hard_negative: bool
    source: Literal["construction", "catalog", "adjudication"]

    @model_validator(mode="after")
    def _status_constraints(self) -> Self:
        if len(set(self.categories)) != len(self.categories):
            raise ValueError("categories 중복")
        if self.label_status == "labeled_positive":
            ok = bool(self.categories) and bool(self.anchors) and not self.hard_negative
        elif self.label_status == "verified_clean":  # hard negative면 흉내 낸 category, 아니면 비움. anchors는 항상 비움
            ok = not self.anchors and (bool(self.categories) if self.hard_negative else not self.categories)
        else:
            ok = not self.categories and not self.anchors and not self.hard_negative
        if not ok:
            raise ValueError("label_status 제약 위반")
        return self


class FrozenAgainst(_Strict):
    envelope_schema: str
    raw_schema: str
    labelfile_schema: str
    masking_modes: dict[UUID, MaskingMode]  # 생산 조건(정답 아님) — Envelope마다 어느 모드로 마스킹했나


class LabelFile(_Strict):
    schema_version: Literal["1.0"]
    dataset_id: str
    frozen_at: AwareDatetime
    frozen_against: FrozenAgainst
    labels: Annotated[list[Label], Field(min_length=1)]

    @model_validator(mode="after")
    def _one_label_per_transaction(self) -> Self:
        refs = [label.transaction_ref for label in self.labels]
        if len(set(refs)) != len(refs) or set(refs) != set(self.frozen_against.masking_modes):
            raise ValueError("라벨·모드 기록이 트랜잭션마다 정확히 하나가 아님")
        return self


def anchor_problems(label_file: LabelFile, transactions: dict[UUID, Transaction]) -> list[str]:
    """라벨 무결성 위반(사유 코드@구조 위치). 비어 있어야 동결한다."""
    problems: list[str] = []
    for i, label in enumerate(label_file.labels):
        tx = transactions.get(label.transaction_ref)
        if tx is None:
            problems.append(f"transaction_missing@labels[{i}]")
            continue
        for j, anchor in enumerate(label.anchors):
            canonical_address(tx, anchor)  # (가) CNA로 정규화됨 — 타입이 보장하므로 실패 경로 없음
            if not output_gate.resolves(anchor, tx):  # (나) 실제 위치
                problems.append(f"anchor_unresolvable@labels[{i}].anchors[{j}]")
    return problems
