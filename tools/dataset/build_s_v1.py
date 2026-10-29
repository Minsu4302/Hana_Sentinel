"""평가 데이터셋 S v1 생성기 — 첫 동결((A) §6.2). 실행은 한 번이고, 결과(마스킹된 Envelope + 라벨 파일)를 그대로 커밋한다.

다시 실행하면 토큰·트랜잭션 ID가 새로 만들어져 다른 바이트가 나온다 — 재현이 아니라 동결이다. 이미 있는 데이터셋
디렉터리에는 쓰지 않는다(동결 자산 덮어쓰기 금지 — 재심은 새 데이터셋 버전으로만).

원본은 메모리에서만 만든다: RawEnvelope를 디스크에 쓰지 않고 `masker.mask`에 바로 넘긴다((A) §1.3 ⓕ). 값은 N5 더미
(faketoken_…·*.example.test). 라벨은 더미 API 정의(아래 CASES)에서 파생한다 — source=construction(§6.2).
쓰기 전에 라벨 무결성·엔진 회귀·모드 정합을 모두 통과해야 한다(하나라도 실패하면 아무것도 쓰지 않음).

실행: `PYTHONPATH=src python -m tools.dataset.build_s_v1 [출력 디렉터리]`(기본 datasets/S/v1).
"""
from __future__ import annotations

import json
import secrets
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sentinel.pipeline import schema_gate
from tools.dataset.freeze import current_versions, engine_regression_problems, mode_problems, version_freeze_problems
from tools.dataset.labelfile import LabelFile, anchor_problems
from tools.fixture_masker import masker
from tools.fixture_masker.raw import RawEnvelope

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "datasets" / "S" / "v1"
DATASET_ID = "S-v1"


def _tok() -> str:
    return f"faketoken_{secrets.token_hex(8)}"


def _json(doc) -> dict:
    return {"content_type": "application/json", "encoding": "utf8", "content": json.dumps(doc)}


def _tx(method: str, path: str, *, params=(), headers=(), body=None, status=200, resp_headers=(), resp_body=None) -> dict:
    return {"meta": {"transaction_id": str(uuid.uuid4()), "captured_at": "2026-10-29T10:00:00+09:00",
                     "origin_ref": f"burp-{secrets.token_hex(2)}"},
            "request": {"method": method, "scheme": "http", "host": "shop.example.test", "port": 3000, "path": path,
                        "query_params": list(params),
                        "headers": [{"name": "Host", "value": "shop.example.test"},
                                    {"name": "Cookie", "value": f"sid={_tok()}"}, *headers],
                        "body": body or {"content_type": "text/plain", "encoding": "utf8", "content": ""}},
            "response": {"status": status, "headers": [{"name": "Content-Type", "value": "application/json"},
                                                       *resp_headers],
                         "body": resp_body or _json({"status": "ok"}), "elapsed_ms": 12}}


def cases() -> list[dict]:
    """(원본 트랜잭션, 모드, 라벨 정의). anchors는 마스킹 후 Envelope를 가리키는 Locator."""
    payload = "<script>alert(1)</script>"
    return [
        {"name": "reflected_search", "mode": "strict_redaction",
         "tx": _tx("GET", "/rest/products/search", params=[{"name": "q", "value": payload, "location": "query"}],
                   resp_body=_json({"data": [], "query": payload})),
         "label": {"label_status": "labeled_positive", "categories": ["reflected_injection_indicator"],
                   "anchors": [{"locus": "req_param", "location": "query", "name": "q"},
                               {"locus": "resp_body", "body": {"kind": "json", "path": "/query"}}]}},
        {"name": "stack_trace", "mode": "strict_redaction",
         "tx": _tx("GET", "/rest/products/0", status=500,
                   resp_body=_json({"error": {"message": "SQLITE_ERROR: no such row",
                                              "stack": "Error\n    at /app/routes/product.ts:41:13"}})),
         "label": {"label_status": "labeled_positive", "categories": ["info_exposure"],
                   "anchors": [{"locus": "resp_body", "body": {"kind": "json", "path": "/error/stack"}}]}},
        {"name": "cors_wildcard_credentials", "mode": "strict_redaction",
         "tx": _tx("GET", "/api/Users/whoami",
                   resp_headers=[{"name": "Access-Control-Allow-Origin", "value": "*"},
                                 {"name": "Access-Control-Allow-Credentials", "value": "true"}]),
         "label": {"label_status": "labeled_positive", "categories": ["security_misconfig"],
                   "anchors": [{"locus": "resp_header", "name": "access-control-allow-origin"},
                               {"locus": "resp_header", "name": "access-control-allow-credentials"}]}},
        {"name": "idor_basket", "mode": "relation_preserving",  # IDOR: 내 토큰으로 남의 장바구니(헤더·본문 걸침)
         "tx": _tx("GET", "/rest/basket/7", headers=[{"name": "Authorization", "value": f"Bearer {_tok()}"}],
                   resp_body=_json({"data": {"id": 7, "UserId": 2, "owner_token": _tok(), "Products": []}})),
         "label": {"label_status": "labeled_positive", "categories": ["access_control"],
                   "anchors": [{"locus": "req_header", "name": "authorization"},
                               {"locus": "resp_body", "body": {"kind": "json", "path": "/data/UserId"}}]}},
        {"name": "product_list_clean", "mode": "strict_redaction",
         "tx": _tx("GET", "/rest/products", resp_body=_json({"data": [{"id": 1, "name": "Apple Juice"}]})),
         "label": {"label_status": "verified_clean", "categories": [], "anchors": []}},
        {"name": "escaped_search_hard_negative", "mode": "strict_redaction",  # 반사되지만 이스케이프됨 — 취약해 보이나 아님
         "tx": _tx("GET", "/rest/products/search", params=[{"name": "q", "value": "O'Reilly", "location": "query"}],
                   resp_body=_json({"data": [], "query": "O&#39;Reilly"})),
         "label": {"label_status": "verified_clean", "categories": ["reflected_injection_indicator"], "anchors": [],
                   "hard_negative": True}},
    ]


def build(out_dir: Path = DEFAULT_OUT) -> list[str]:
    """데이터셋을 만들고 검사한다. 문제가 있으면 목록을 돌려주고 아무것도 쓰지 않는다."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        return ["dataset_exists"]
    specs = cases()
    files: dict[str, bytes] = {}
    for mode in ("strict_redaction", "relation_preserving"):
        group = [s for s in specs if s["mode"] == mode]
        raw = RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": [s["tx"] for s in group]}))
        files.update(masker.mask(raw, mode))
    versions = current_versions()
    labels = {"schema_version": "1.0", "dataset_id": DATASET_ID,
              "frozen_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
              "frozen_against": {**versions, "masking_modes": {s["tx"]["meta"]["transaction_id"]: s["mode"] for s in specs}},
              "labels": [{"transaction_ref": s["tx"]["meta"]["transaction_id"], "hard_negative": False,
                          "source": "construction", **s["label"]} for s in specs]}
    label_bytes = (json.dumps(labels, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    label_file = LabelFile.model_validate_json(label_bytes)
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


def _write(out_dir: Path, files: dict[str, bytes], label_bytes: bytes) -> None:
    (out_dir / "envelopes").mkdir(parents=True)
    for name, data in files.items():
        (out_dir / "envelopes" / name).write_bytes(data)
    (out_dir / "labels.json").write_bytes(label_bytes)


if __name__ == "__main__":
    problems = build(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT)
    print("dataset frozen" if not problems else "dataset not written: " + " ".join(problems))
    sys.exit(1 if problems else 0)
