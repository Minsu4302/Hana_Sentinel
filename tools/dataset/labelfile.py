"""평가 라벨 파일 — (A) §6.2 LabelFile·Label, 라벨 무결성.

버전: 1.0(S v1) = 트랜잭션마다 라벨 정확히 1개, split·ruleset 기록 없음 / 1.1 = 결함별 라벨(트랜잭션마다 ≥ 1 — verified_clean·
unlabeled는 단독), split_scheme이 있으면 라벨별 split 필수, frozen_against의 ruleset_version·ruleset_hash 필수.

라벨 무결성(동결 전에 막는다 — 예측 Evidence 무결성과 같은 검증을 라벨에):
- (가) anchor는 Locator(§2.6) 타입으로만 읽힌다(스키마가 보장). `canonical_address`가 CNA를 돌려준다.
- (나) 실질 방어: anchor가 transaction_ref가 가리키는 마스킹된 Envelope에서 실제로 해석된다 — 출력 게이트의 공개 판정
  `output_gate.resolves`를 그대로 쓴다(예측 evidence와 라벨 anchor가 같은 정의). 없는 위치를 가리키면 그 라벨은 거부.
라벨링 지침(§6.1 — 거친 노드 body_text·req_line.path를 더 세밀한 노드가 있을 때 anchor로 쓰지 않음)은 라벨러가 지키는
지침이며 여기서 기계 강제하지 않는다.
"""
from __future__ import annotations

from typing import Annotated, Final, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from sentinel.canonical_address import canonical_address
from sentinel.common_types import Locator
from sentinel.output_schema import Category
from sentinel.pipeline import output_gate
from sentinel.schema import Transaction

LABELFILE_SCHEMA_VERSION = "1.1"
SUPPORTED_LABELFILE_SCHEMAS: Final = ("1.0", "1.1")
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
    split: Literal["dev", "test"] | None = None

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
    ruleset_version: str | None = None
    ruleset_hash: str | None = None
    masking_modes: dict[UUID, MaskingMode]  # 생산 조건(정답 아님) — Envelope마다 어느 모드로 마스킹했나


class LabelFile(_Strict):
    schema_version: Literal["1.0", "1.1"]
    dataset_id: str
    frozen_at: AwareDatetime
    split_scheme: Literal["endpoint"] | None = None
    frozen_against: FrozenAgainst
    labels: Annotated[list[Label], Field(min_length=1)]

    @model_validator(mode="after")
    def _labels_match_transactions(self) -> Self:
        groups: dict[UUID, list[Label]] = {}
        for label in self.labels:
            groups.setdefault(label.transaction_ref, []).append(label)
        if set(groups) != set(self.frozen_against.masking_modes):
            raise ValueError("라벨과 모드 기록의 트랜잭션이 다름")
        if self.schema_version == "1.0":
            self._check_1_0(groups)
        else:
            self._check_1_1(groups)
        return self

    def _check_1_0(self, groups: dict[UUID, list[Label]]) -> None:
        if any(len(g) != 1 for g in groups.values()):
            raise ValueError("1.0: 라벨이 트랜잭션마다 정확히 하나가 아님")
        recorded = (self.split_scheme, self.frozen_against.ruleset_version, self.frozen_against.ruleset_hash)
        if any(v is not None for v in recorded) or any(label.split is not None for label in self.labels):
            raise ValueError("1.0에는 split·ruleset 기록이 없다")

    def _check_1_1(self, groups: dict[UUID, list[Label]]) -> None:
        if self.frozen_against.ruleset_version is None or self.frozen_against.ruleset_hash is None:
            raise ValueError("1.1: ruleset_version·ruleset_hash 필수")
        for group in groups.values():
            if len(group) > 1 and any(label.label_status != "labeled_positive" for label in group):
                raise ValueError("1.1: verified_clean·unlabeled는 그 트랜잭션의 유일한 라벨")
            if len({label.split for label in group}) != 1:
                raise ValueError("1.1: 한 트랜잭션의 split이 갈림")
        if self.split_scheme is not None and any(label.split is None for label in self.labels):
            raise ValueError("1.1: split_scheme이 있으면 라벨의 split은 필수")
        if self.split_scheme is None and any(label.split is not None for label in self.labels):
            raise ValueError("1.1: split_scheme 없이 split을 적을 수 없다")


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
