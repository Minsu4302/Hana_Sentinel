"""fixture 마스커(마스커-A) — RawEnvelope(§2.7) → 마스킹된 Envelope(§2.1·§2.2). (A) §1.3 ⓕ 경계의 참조 구현.

이 단계의 핵심은 변환 품질이 아니라 '원본이 어디에도 새지 않음'이다:
- 입력 경로는 레포 밖이어야 한다(레포 안 → 거부). 원본이 레포에 들어오는 것 자체를 막는다.
- 원본 평문은 메모리에서만 다룬다. 디스크에는 마스킹된 Envelope만 쓰고, 로그·stdout/stderr·예외 메시지에는
  사유 코드와 개수만 남긴다. 변환 중 예외는 사유 코드 하나로 바꾸고 원 예외 체인을 끊는다(`from None`).
- 유출 검사(fail-closed): 마스킹한 원본 값(헤더 값·호스트)이 출력의 어느 문자열에든 남아 있으면 아무것도 쓰지 않고
  거부한다. 변환 버그나, 마스킹하지 않는 자리(본문·다른 헤더·경로)에 같은 값이 있는 입력이 여기서 걸린다.

변환 범위(A): 정책 헤더(`sentinel.sanitization_policy` — 마스커와 Java가 같은 정책을 해석, (A) §2.3) → MaskedRef,
Host 헤더 → MaskedRef(kind=host), request.host → 가명. 라벨은 실행 안 단순 순번(`ref_NN`). 본문은 바꾸지 않는다 —
본문 masked_spans·라벨 일관성(같은 원본값 ⇔ 같은 라벨)·CNA·절단은 마스커-B 이후. size_bytes는 마스킹 뒤 출력 content로
산출하고 truncated=false(절단하지 않음 — §2.2 절단은 마스킹 뒤).

독립성(`masker_independence`, R-11): 엔진 검증 파이프라인(`sentinel.pipeline`, ③ sanitization_check 포함)을 쓰지 않는다.
엔진의 공용 정의(`sentinel.schema` 출력 타입·`sentinel.strict_json` 엄격 JSON·정책 데이터)는 쓴다 — 검증 로직이 아니다.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from sentinel import strict_json
from sentinel.sanitization_policy import DEFAULT_POLICY
from sentinel.schema import Envelope
from tools.fixture_masker.raw import RAW_SCHEMA_VERSION, RawBody, RawEnvelope, RawHeader, RawTransaction

log = logging.getLogger("fixture_masker")

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
POLICY: Final = DEFAULT_POLICY
MAX_LABEL: Final = 9999  # MaskLabel = ref_ + 숫자 2~4자리
# 유출 검사에서 값 전체와 함께 찾는 구성요소: 구분자(공백·;·,·=)로 나눈 조각 중 이 길이 이상.
# 'sid=<토큰>'·'Bearer <토큰>'에서 토큰만 다른 자리로 새는 경우를 잡는다. 짧은 조각(쿠키 이름·스킴)은 제외 — 오탐 방지.
MIN_FRAGMENT: Final = 8
_SEPARATORS: Final = re.compile(r"[\s;,=]+")

REASON_CODES: Final = (
    "input_inside_repo",      # 원본 입력 경로가 레포 안
    "input_unreadable",
    "input_not_json",         # UTF-8·엄격 JSON(§2.6 정의)이 아님
    "unknown_schema_version",
    "raw_schema_invalid",     # RawEnvelope 위반(마스킹 산출물 필드 혼입 포함)
    "transform_failed",
    "label_space_exhausted",
    "masked_value_leaked",    # 마스킹한 원본 값이 출력에 남음 — 아무것도 쓰지 않음
    "output_build_failed",
    "output_exists",
)


class MaskerRejected(Exception):
    """거부·실패. 사유 코드만 담는다(경로·값·입력 필드명 없음)."""

    def __init__(self, code: str):
        assert code in REASON_CODES
        self.code = code
        super().__init__(code)


# ── 입력 ──────────────────────────────────────────────────────────

def _inside_repo(path: Path) -> bool:
    target = os.path.normcase(str(path.resolve()))
    root = os.path.normcase(str(REPO_ROOT))
    return target == root or target.startswith(root.rstrip("\\/") + os.sep)


def load_raw(path: Path) -> RawEnvelope:
    path = Path(path)
    if _inside_repo(path):
        raise MaskerRejected("input_inside_repo")
    try:
        data = path.read_bytes()
    except OSError:
        raise MaskerRejected("input_unreadable") from None
    try:
        doc = strict_json.parse(data.decode("utf-8"))
    except ValueError:  # UnicodeDecodeError 포함
        raise MaskerRejected("input_not_json") from None
    if not isinstance(doc, dict) or doc.get("schema_version") != RAW_SCHEMA_VERSION:
        raise MaskerRejected("unknown_schema_version")
    try:
        return RawEnvelope.model_validate_json(data)
    except ValidationError:
        raise MaskerRejected("raw_schema_invalid") from None  # 오류 메시지·위치에 입력 값이 있다 — 버린다


# ── 변환 ──────────────────────────────────────────────────────────

class _Run:
    """한 번의 실행 상태. 마스킹한 원본 값은 유출 검사에만 쓰고 실행이 끝나면 버린다."""

    def __init__(self) -> None:
        self.labels = 0
        self.hosts = 0
        self.originals: list[str] = []

    def label(self) -> str:
        self.labels += 1
        if self.labels > MAX_LABEL:
            raise MaskerRejected("label_space_exhausted")
        return f"ref_{self.labels:02d}"

    def masked(self, original: str, kind: str) -> dict[str, Any]:
        self.originals.append(original)
        return {"masked": True, "label": self.label(), "kind": kind}


def _header_kind(name: str) -> str | None:
    lowered = name.lower()
    if lowered == "host":
        return "host"
    if POLICY.requires_masked_header(name):
        return "cookie" if "cookie" in lowered else "token"
    return None


def _header(h: RawHeader, run: _Run) -> dict[str, Any]:
    kind = _header_kind(h.name)
    return {"name": h.name, "value": h.value if kind is None else run.masked(h.value, kind)}


def _body(b: RawBody) -> dict[str, Any]:
    if b.encoding == "omitted" or b.content is None:
        size = 0
    elif b.encoding == "base64":
        size = len(base64.b64decode(b.content, validate=True))  # 디코드 불가 → transform_failed
    else:
        size = len(b.content.encode("utf-8"))
    return {"content_type": b.content_type, "size_bytes": size, "truncated": False, "encoding": b.encoding,
            "content": None if b.encoding == "omitted" else b.content, "masked_spans": []}


def _transaction(tx: RawTransaction, run: _Run) -> dict[str, Any]:
    start = run.labels
    req, resp = tx.request, tx.response
    run.originals.append(req.host)
    run.hosts += 1
    out = {
        "meta": {"transaction_id": str(tx.meta.transaction_id), "captured_at": tx.meta.captured_at.isoformat(),
                 "origin_ref": tx.meta.origin_ref, "sanitization": None},
        "request": {"method": req.method, "scheme": req.scheme, "host": f"masked-host-{run.hosts:02d}.invalid",
                    "port": req.port, "path": req.path,
                    "query_params": [{"name": p.name, "value": p.value, "location": p.location} for p in req.query_params],
                    "headers": [_header(h, run) for h in req.headers], "body": _body(req.body)},
        "response": {"status": resp.status, "headers": [_header(h, run) for h in resp.headers],
                     "body": _body(resp.body), "elapsed_ms": resp.elapsed_ms},
    }
    kinds = {"token": 0, "cookie": 0, "pii": 0, "host": 0}
    for h in out["request"]["headers"] + out["response"]["headers"]:
        if isinstance(h["value"], dict):
            kinds[h["value"]["kind"]] += 1
    out["meta"]["sanitization"] = {"applied": True, "failed": False, "policy_version": POLICY.policy_version,
                                   "redacted_count": run.labels - start, "redacted_kinds": kinds}
    return out


def _string_leaves(node: Any):
    if isinstance(node, dict):
        for v in node.values():
            yield from _string_leaves(v)
    elif isinstance(node, list):
        for v in node:
            yield from _string_leaves(v)
    elif isinstance(node, str):
        yield node


def _needles(originals: list[str]) -> set[str]:
    found = {o for o in originals if o}
    for o in originals:
        found.update(part for part in _SEPARATORS.split(o) if len(part) >= MIN_FRAGMENT)
    return found


def _leaked(serialized: list[str], originals: list[str]) -> bool:
    """마스킹한 원본 값(또는 그 구성요소)이 출력 문자열 어디에든 남았는가. JSON 이스케이프와 무관하게 파싱한 값에서 본다."""
    needles = _needles(originals)
    return any(n in leaf for text in serialized for leaf in _string_leaves(json.loads(text)) for n in needles)


def mask(raw: RawEnvelope) -> list[tuple[str, bytes]]:
    """(파일 이름, 마스킹된 Envelope 바이트) 목록. 유출 검사를 통과한 것만 돌려준다."""
    run = _Run()
    try:
        drafts = [_transaction(tx, run) for tx in raw.transactions]
    except MaskerRejected:
        raise
    except Exception:
        raise MaskerRejected("transform_failed") from None  # 원 예외 메시지에 원본 조각이 있을 수 있다 — 체인을 끊는다
    try:
        envelopes = [Envelope.model_validate_json(json.dumps(
            {"schema_version": "1.0", "analysis_type": "single", "transactions": [d]}, ensure_ascii=False))
            for d in drafts]
    except ValidationError:
        raise MaskerRejected("output_build_failed") from None
    serialized = [e.model_dump_json() for e in envelopes]
    if _leaked(serialized, run.originals):
        raise MaskerRejected("masked_value_leaked")
    return [(f"{e.transactions[0].meta.transaction_id}.json", s.encode("utf-8")) for e, s in zip(envelopes, serialized)]


# ── 출력 ──────────────────────────────────────────────────────────

def run(raw_path: Path, out_dir: Path) -> int:
    """원본 파일 → out_dir에 트랜잭션마다 Envelope 하나. 전부 만든 뒤에만 쓴다(부분 출력 없음)."""
    outputs = mask(load_raw(raw_path))
    out_dir = Path(out_dir)
    if any((out_dir / name).exists() for name, _ in outputs):
        raise MaskerRejected("output_exists")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in outputs:
        (out_dir / name).write_bytes(data)
    log.info("masked transactions=%d", len(outputs))
    return len(outputs)
