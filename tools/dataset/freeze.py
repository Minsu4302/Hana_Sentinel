"""동결 데이터셋 회귀 검사 — `dataset_version_freeze` · `dataset_engine_regression` · `dataset_mode_consistency`. (A) §2 버전
규칙, §2.3 모드 규칙, §6.2 동결.

데이터셋 디렉터리 = `envelopes/<transaction_id>.json`(마스킹된 Envelope, 마스커 출력 그대로) + `labels.json`(LabelFile —
픽스처와 분리된 파일). 원본(RawTransaction)은 없다 — 커밋하지 않는다((A) §1.3 ⓕ).

- version_freeze_problems: 동결 Envelope·라벨 파일이 현재 스키마로 읽히지 않는데 그 스키마 버전이 동결 시점과 같으면 실패
  (스키마를 바꾸고 버전을 올리지 않은 것). 버전이 올라갔다면 이 검사는 실패하지 않는다 — 그때는 새 데이터셋 버전으로
  다시 동결해야 하고, 엔진 회귀 검사가 옛 데이터를 거부해 그것을 드러낸다. Raw 스키마는 동결 파일이 없어(원본 커밋 0)
  버전만 기록하고 검증할 대상이 없다.
- engine_regression_problems: 동결 Envelope마다 엔진의 실제 ②③(`tools.masker_cross_check.engine_verdict`) 통과. 모드 무관 —
  엔진 ③은 모드를 모른다.
- mode_problems: 동결 자산이 기록된 마스킹 모드와 맞는가((A) §2.3) — strict_redaction이면 모든 MaskedRef 라벨이 null,
  relation_preserving이면 모두 ref_NN(그리고 MaskedRef가 하나 이상 — 라벨 없는 relation 기록은 검사할 게 없어 거부).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, get_args
from uuid import UUID

from sentinel.canonical_address import canonical_address
from sentinel.pipeline import schema_gate
from sentinel.schema import Envelope
from tools.dataset.labelfile import LABELFILE_SCHEMA_VERSION, LabelFile
from tools.fixture_masker.raw import RAW_SCHEMA_VERSION
from tools.masker_cross_check import engine_verdict

REF_LABEL = re.compile(r"^ref_[0-9]{2,4}$")


def current_versions() -> dict[str, str]:
    [envelope] = get_args(Envelope.model_fields["schema_version"].annotation)
    return {"envelope_schema": envelope, "raw_schema": RAW_SCHEMA_VERSION, "labelfile_schema": LABELFILE_SCHEMA_VERSION}


def envelope_files(dataset: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted((Path(dataset) / "envelopes").glob("*.json"))}


def _frozen_against(dataset: Path) -> dict[str, Any]:
    return json.loads((Path(dataset) / "labels.json").read_bytes())["frozen_against"]


def version_freeze_problems(dataset: Path) -> list[str]:
    frozen, now, problems = _frozen_against(dataset), current_versions(), []
    envelopes_ok = True
    for data in envelope_files(dataset).values():
        try:
            schema_gate.parse_envelope(data)
        except schema_gate.SchemaRejected:
            envelopes_ok = False
    if not envelopes_ok and frozen["envelope_schema"] == now["envelope_schema"]:
        problems.append("envelope_schema_changed_without_version_bump")
    try:
        label_file = LabelFile.model_validate_json((Path(dataset) / "labels.json").read_bytes())
        txs = {e.transactions[0].meta.transaction_id: e.transactions[0]
               for e in (schema_gate.parse_envelope(d) for d in envelope_files(dataset).values())}
        for label in label_file.labels:
            for anchor in label.anchors:
                canonical_address(txs[label.transaction_ref], anchor)
        labels_ok = True
    except Exception:  # 스키마 불일치·anchor 정규화 불가 — 무엇이든 '현재 스키마로 읽히지 않음'
        labels_ok = False
    if not labels_ok and frozen["labelfile_schema"] == now["labelfile_schema"]:
        problems.append("labelfile_schema_changed_without_version_bump")
    return problems


def engine_regression_problems(dataset: Path) -> list[str]:
    problems = []
    for name, data in envelope_files(dataset).items():
        verdict, reasons = engine_verdict(data)
        if verdict != "accepted":
            problems.append(f"{verdict}:{','.join(reasons)}@{name}")
    return problems


def _masked_refs(tx: dict[str, Any]):
    for side in ("request", "response"):
        for h in tx[side]["headers"]:
            if isinstance(h["value"], dict):
                yield h["value"]
        for span in tx[side]["body"]["masked_spans"]:
            yield span["ref"]
    for p in tx["request"]["query_params"]:
        if isinstance(p["value"], dict):
            yield p["value"]


def mode_problems(dataset: Path) -> list[str]:
    modes = {UUID(k): v for k, v in _frozen_against(dataset)["masking_modes"].items()}
    problems = []
    for name, data in envelope_files(dataset).items():
        tx = json.loads(data)["transactions"][0]
        mode = modes.get(UUID(tx["meta"]["transaction_id"]))
        labels = [ref["label"] for ref in _masked_refs(tx)]
        if mode is None:
            problems.append(f"mode_not_recorded@{name}")
        elif mode == "strict_redaction" and any(label is not None for label in labels):
            problems.append(f"strict_with_label@{name}")
        elif mode == "relation_preserving" and (not labels or not all(
                isinstance(label, str) and REF_LABEL.match(label) for label in labels)):
            problems.append(f"relation_without_ref_label@{name}")
    return problems
