"""S v2 생성기 — 선언형 사례 카탈로그 → RawEnvelope → 마스커 → Envelope + LabelFile 1.1. (A) §6.2 S v2 구성.

카탈로그가 SSOT다. 검사가 하나라도 실패하면 아무것도 쓰지 않는다:
- 지침: 카탈로그 머리의 버전·해시가 동결 표와 같고 현재 지침 파일도 그 해시다(`guideline_freeze`)
- 규칙: 현재 규칙 해시가 동결 표의 RULESET_VERSION 항목과 같다(`producer_freeze_order`)
- (엔드포인트, 패턴) 조합 중복 0(`dataset_case_independence`), 엔드포인트 단위 split, 규모 게이트, 조항 ID, 구성 조건

결함별 라벨이라 카탈로그의 라벨은 사례마다 목록이다. 라벨 위반(hard_negative가 positive에 등)은 `LabelFile`이 거부한다.
토큰 값은 카탈로그에 적지 않는다: `${tok:이름}`을 빌드마다 더미로 바꾼다(같은 이름 = 같은 값, 마스킹 전 값 커밋 0).
동결이지 재현이 아니다 — 다시 실행하면 토큰·트랜잭션 ID가 달라진다. 이미 있는 디렉터리에는 쓰지 않는다.

실행: `PYTHONPATH=src python -m tools.dataset.generator <카탈로그.json> <출력 디렉터리>`
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import sys
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.common_types import Locator
from sentinel.output_schema import Category
from sentinel.pipeline import rule_engine, schema_gate
from tools.dataset.build_s_v1 import _write
from tools.dataset.freeze import current_versions, engine_regression_problems, mode_problems, version_freeze_problems
from tools.dataset.labelfile import LABELFILE_SCHEMA_VERSION, LabelFile, MaskingMode, anchor_problems
from tools.eval.frozen_rulesets import FROZEN_GUIDELINES, FROZEN_RULESETS, current_ruleset_hash, guideline_is_frozen
from tools.fixture_masker import masker
from tools.fixture_masker.raw import RawEnvelope

REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDELINE_PATH: Final = REPO_ROOT / "docs" / "labeling-guideline.md"
REQUEST_HOST: Final = "shop.example.test"
SPLIT_GATES: Final = {"test": (39, 39), "dev": (20, 20)}  # (labeled_positive 트랜잭션, verified_clean 트랜잭션)
CATEGORY_GATE: Final = (8, 4)                             # test의 category마다 (positive 트랜잭션, hard negative 트랜잭션)
CATEGORIES: Final = ("access_control", "info_exposure", "reflected_injection_indicator", "security_misconfig")
TOKEN: Final = re.compile(r"\$\{tok:([a-z0-9_]+)\}")


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Endpoint(_Strict):
    method: str
    path_template: str


class GuidelineRef(_Strict):
    version: str
    hash: str


class CaseLabel(_Strict):
    label_status: Literal["labeled_positive", "verified_clean", "unlabeled"]
    categories: list[Category]
    anchors: list[Locator]
    hard_negative: bool = False
    clause: str | None = None  # 지침 조항 ID. positive·hard negative는 필수


class CaseTx(_Strict):
    scheme: Literal["http", "https"] = "http"
    path: str
    params: list[dict[str, str]] = []
    headers: list[dict[str, str]] = []
    status: int = 200
    resp_headers: list[dict[str, str]] = []
    resp_content_type: str = "application/json"
    resp_json: Any = None
    resp_text: str | None = None


class Case(_Strict):
    case_id: str
    endpoint: Endpoint
    pattern_id: str
    split: Literal["dev", "test"]
    masking_mode: MaskingMode
    source: Literal["construction", "catalog", "adjudication"]
    labels: Annotated[list[CaseLabel], Field(min_length=1)]
    tx: CaseTx


class Catalog(_Strict):
    dataset_id: str
    guideline: GuidelineRef
    cases: list[Case]


# ── 검사 ───────────────────────────────────────────────────────────

def guideline_problems(catalog: Catalog) -> list[str]:
    ref = catalog.guideline
    if FROZEN_GUIDELINES.get(ref.version) != ref.hash or not guideline_is_frozen(GUIDELINE_PATH, ref.version):
        return ["guideline_not_frozen"]
    return []


def ruleset_problems(_catalog: Catalog) -> list[str]:
    if FROZEN_RULESETS.get(rule_engine.RULESET_VERSION) != current_ruleset_hash():
        return ["ruleset_not_frozen"]
    return []


def independence_problems(catalog: Catalog) -> list[str]:
    pairs = Counter((c.endpoint, c.pattern_id) for c in catalog.cases)
    ids = Counter(c.case_id for c in catalog.cases)
    return (["duplicate_endpoint_pattern"] if max(pairs.values(), default=0) > 1 else []) + \
           (["duplicate_case_id"] if max(ids.values(), default=0) > 1 else [])


def endpoint_split_problems(catalog: Catalog) -> list[str]:
    splits: dict[Endpoint, set[str]] = {}
    for c in catalog.cases:
        splits.setdefault(c.endpoint, set()).add(c.split)
    return ["endpoint_in_two_splits"] if any(len(s) > 1 for s in splits.values()) else []


def _is_positive(case: Case) -> bool:
    return any(label.label_status == "labeled_positive" for label in case.labels)


def _is_clean(case: Case) -> bool:
    return case.labels[0].label_status == "verified_clean"


def scale_problems(catalog: Catalog) -> list[str]:
    """트랜잭션 수로 센다. hard negative는 verified_clean 트랜잭션만이다."""
    problems = []
    for split, (positives, cleans) in SPLIT_GATES.items():
        cases = [c for c in catalog.cases if c.split == split]
        if sum(_is_positive(c) for c in cases) < positives:
            problems.append(f"scale_positive@{split}")
        if sum(_is_clean(c) for c in cases) < cleans:
            problems.append(f"scale_clean@{split}")
    test = [c for c in catalog.cases if c.split == "test"]
    for category in CATEGORIES:
        positive = sum(any(label.label_status == "labeled_positive" and category in label.categories for label in c.labels)
                       for c in test)
        hard = sum(_is_clean(c) and c.labels[0].hard_negative and category in c.labels[0].categories for c in test)
        if positive < CATEGORY_GATE[0]:
            problems.append(f"scale_category_positive@{category}")
        if hard < CATEGORY_GATE[1]:
            problems.append(f"scale_category_hard_negative@{category}")
    return problems


def clause_problems(catalog: Catalog) -> list[str]:
    text = GUIDELINE_PATH.read_text(encoding="utf-8")
    for c in catalog.cases:
        for label in c.labels:
            if label.label_status == "labeled_positive" or label.hard_negative:
                if label.clause is None or f"- **{label.clause} " not in text:
                    return ["clause_unknown"]
    return []


def _origin_is_foreign(case: Case) -> bool:
    origins = [h["value"] for h in case.tx.headers if h["name"].lower() == "origin"]
    return len(origins) == 1 and urlsplit(origins[0]).hostname not in (None, "", REQUEST_HOST)


def _is_https(case: Case) -> bool:
    return case.tx.scheme == "https"


CONSTRUCTION_CHECKS: Final = {"SM-P2": _origin_is_foreign, "SM-P4": _is_https, "SM-N3": _is_https}


def construction_problems(catalog: Catalog) -> list[str]:
    for c in catalog.cases:
        for label in c.labels:
            check = CONSTRUCTION_CHECKS.get(label.clause)
            if check is not None and not check(c):
                return [f"construction@{label.clause}"]
    return []


CHECKS: Final = (guideline_problems, ruleset_problems, independence_problems, endpoint_split_problems, scale_problems,
                 clause_problems, construction_problems)


def catalog_problems(catalog: Catalog) -> list[str]:
    return [p for check in CHECKS for p in check(catalog)]


# ── 생성 ───────────────────────────────────────────────────────────

def _filled(value: Any, tokens: dict[str, str]) -> Any:
    if isinstance(value, str):
        return TOKEN.sub(lambda m: tokens.setdefault(m.group(1), f"faketoken_{secrets.token_hex(8)}"), value)
    if isinstance(value, list):
        return [_filled(v, tokens) for v in value]
    if isinstance(value, dict):
        return {k: _filled(v, tokens) for k, v in value.items()}
    return value


def _raw_tx(case: Case, ref: str, tokens: dict[str, str]) -> dict[str, Any]:
    tx = case.tx
    content = tx.resp_text if tx.resp_text is not None else json.dumps(tx.resp_json)
    doc = {"meta": {"transaction_id": ref, "captured_at": "2026-11-04T10:00:00+09:00",
                    "origin_ref": f"burp-{secrets.token_hex(2)}"},
           "request": {"method": case.endpoint.method, "scheme": tx.scheme, "host": REQUEST_HOST, "port": 3000, "path": tx.path,
                       "query_params": tx.params, "headers": [{"name": "Host", "value": REQUEST_HOST}, *tx.headers],
                       "body": {"content_type": "text/plain", "encoding": "utf8", "content": ""}},
           "response": {"status": tx.status, "headers": [{"name": "Content-Type", "value": tx.resp_content_type}, *tx.resp_headers],
                        "body": {"content_type": tx.resp_content_type, "encoding": "utf8", "content": content}, "elapsed_ms": 12}}
    return _filled(doc, tokens)


def _label_doc(catalog: Catalog, refs: dict[str, str]) -> bytes:
    labels = [{"transaction_ref": refs[c.case_id], "label_status": label.label_status, "categories": label.categories,
               "anchors": [a.model_dump(mode="json", exclude_none=True) for a in label.anchors],
               "hard_negative": label.hard_negative, "source": c.source, "split": c.split}
              for c in catalog.cases for label in c.labels]
    doc = {"schema_version": LABELFILE_SCHEMA_VERSION, "dataset_id": catalog.dataset_id,
           "frozen_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "split_scheme": "endpoint",
           "frozen_against": {**current_versions(), "ruleset_version": rule_engine.RULESET_VERSION,
                              "ruleset_hash": current_ruleset_hash(),
                              "masking_modes": {refs[c.case_id]: c.masking_mode for c in catalog.cases}},
           "labels": labels}
    return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def build(catalog: Catalog, out_dir: Path) -> list[str]:
    """문제가 있으면 목록을 돌려주고 아무것도 쓰지 않는다."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        return ["dataset_exists"]
    if problems := catalog_problems(catalog):
        return problems
    refs = {c.case_id: str(uuid.uuid4()) for c in catalog.cases}
    tokens: dict[str, str] = {}
    files: dict[str, bytes] = {}
    for mode in ("strict_redaction", "relation_preserving"):
        group = [_raw_tx(c, refs[c.case_id], tokens) for c in catalog.cases if c.masking_mode == mode]
        if group:
            raw = RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": group}))
            files.update(masker.mask(raw, mode))
    label_bytes = _label_doc(catalog, refs)
    try:
        label_file = LabelFile.model_validate_json(label_bytes)
    except ValidationError:
        return ["labelfile_invalid"]
    txs = {e.transactions[0].meta.transaction_id: e.transactions[0]
           for e in (schema_gate.parse_envelope(d) for d in files.values())}
    problems = anchor_problems(label_file, txs)
    with tempfile.TemporaryDirectory() as tmp:  # 쓰기 전 검사는 임시 사본에서
        staged = Path(tmp) / "staged"
        _write(staged, files, label_bytes)
        problems += engine_regression_problems(staged) + mode_problems(staged) + version_freeze_problems(staged)
        if problems:
            return problems
        shutil.copytree(staged, out_dir)
    return []


def main(argv: list[str]) -> int:
    catalog = Catalog.model_validate_json(Path(argv[0]).read_bytes())
    problems = build(catalog, Path(argv[1]))
    print("dataset frozen" if not problems else "dataset not written: " + " ".join(problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
