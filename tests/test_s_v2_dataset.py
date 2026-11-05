"""S v2 동결 자산 — (A) §6.2. 동결 검사·②③·카탈로그 일치만 본다. 규칙(④)은 돌리지 않는다 — 동결 뒤의 첫 실행이 측정이다."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from tools.dataset.generator import Catalog, catalog_problems
from tools.dataset.labelfile import LabelFile
from tools.eval.harness import load_dataset

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "datasets" / "S" / "v2"
CATALOG = REPO_ROOT / "datasets" / "S" / "catalog-v2.json"


def _catalog() -> Catalog:
    return Catalog.model_validate_json(CATALOG.read_bytes())


def test_catalog_passes_every_generator_check():
    assert catalog_problems(_catalog()) == []


def test_dataset_passes_the_freeze_checks_and_records_rules_2():
    label_file, txs = load_dataset(DATASET)
    assert label_file.schema_version == "1.1" and label_file.split_scheme == "endpoint" and len(txs) == 120
    assert label_file.frozen_against.ruleset_version == "rules-2"


def test_dataset_labels_match_the_catalog():
    label_file = LabelFile.model_validate_json((DATASET / "labels.json").read_bytes())
    catalog = _catalog()
    expected = Counter((c.split, label.label_status, tuple(label.categories), label.hard_negative)
                       for c in catalog.cases for label in c.labels)
    assert Counter((x.split, x.label_status, tuple(x.categories), x.hard_negative) for x in label_file.labels) == expected


def test_multi_label_transactions_are_the_planned_ones():
    label_file = LabelFile.model_validate_json((DATASET / "labels.json").read_bytes())
    counts = Counter(x.transaction_ref for x in label_file.labels)
    assert sum(n == 2 for n in counts.values()) == 7 and max(counts.values()) == 2


def test_subject_and_owner_labels_follow_the_relation():
    """AC-N1은 같은 라벨, AC-P1은 다른 라벨이다(라벨은 마스킹되는 값 전체로 정해진다)."""
    label_file, txs = load_dataset(DATASET)
    same = different = 0
    for label in label_file.labels:
        if "access_control" not in label.categories:
            continue
        tx = txs[label.transaction_ref]
        subject = next(h.value.label for h in tx.request.headers if h.name == "X-Auth-Token")
        owner = next(s.ref.label for s in tx.response.body.masked_spans if s.at.path == "/data/owner_token")
        if label.label_status == "labeled_positive":
            assert subject != owner
            different += 1
        else:
            assert subject == owner
            same += 1
    assert (different, same) == (15, 7)


def test_no_generated_token_or_placeholder_is_stored():
    data = b"".join(p.read_bytes() for p in (DATASET / "envelopes").glob("*.json")) + (DATASET / "labels.json").read_bytes()
    assert b"faketoken_" not in data and b"${tok:" not in data


def test_catalog_stores_no_token_value():
    assert "faketoken_" not in json.dumps(json.loads(CATALOG.read_bytes()))
