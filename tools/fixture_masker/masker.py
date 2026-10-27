"""fixture 마스커 — RawEnvelope(§2.7) → 마스킹된 Envelope(§2.1·§2.2). (A) §1.3 ⓕ 경계의 참조 구현.

원본이 어디에도 새지 않음(마스커-A):
- 입력 경로는 레포 밖이어야 한다(레포 안 → 거부). 원본이 레포에 들어오는 것 자체를 막는다.
- 원본 평문은 메모리에서만 다룬다. 디스크에는 마스킹된 Envelope만 쓰고, 로그·stdout/stderr·예외 메시지에는
  사유 코드와 개수만 남긴다. 변환 중 예외는 사유 코드 하나로 바꾸고 원 예외 체인을 끊는다(`from None`).
- 유출 검사(fail-closed): 마스킹한 원본 값과 그 비밀 구성요소(헤더 값 안의 쿠키 값·자격증명 — 이름·스킴 제외)가
  출력의 어느 문자열에든 남아 있으면 아무것도 쓰지 않고 거부한다.

변환(마스커-B1):
- 정책 헤더 → MaskedRef, Host 헤더 → MaskedRef(kind=host), request.host → 가명.
- 본문: 정책 body_rules((A) §2.3 matcher 문법)로 찾은 값을 FILLER로 바꾸고 MaskedSpan을 단다.
  json:<키 glob> = 모든 깊이의 이름 일치 멤버 중 문자열 값 노드(제자리 치환, 노드 전체 span) /
  form:<이름 glob> = 폼 본문 파라미터 값(text range span) + 같은 이름의 Param(location=form) 값도 MaskedRef.
  query 파라미터 규칙은 없다(큐 13) — 거기 남은 마스킹 값은 유출 검사가 거부한다.
- 라벨((A) §2.3 모드 규칙): strict_redaction → label=null / relation_preserving → 매핑 테이블(키 = HMAC(실행 키,
  원본값))의 순번 라벨 ref_NN — 같은 원본값 ⇔ 같은 라벨(kind 무관, 실행 안에서만). 해시를 잘라 라벨로 쓰지 않는다.
  HMAC 키는 실행마다 새로 만들고 실행이 끝나면 버린다(디스크·로그·출력에 쓰지 않음).
- 출력 전 자체 검증: Body 불변식 1~6(엔진 ③을 쓰지 않는 독립 구현), 모드별 라벨 규칙(strict = 전부 null /
  relation = 원본값 ↔ 라벨 양방향 일대일), 유출 검사. 하나라도 어긋나면 아무것도 쓰지 않는다.
- base64 본문(마스커-B2, (A) §2.2 'base64에는 span을 두지 않는다 — 비밀값이 있으면 omitted'): 디코드 바이트를 정책 패턴
  (`sanitization_policy.PATTERNS` — 공유 데이터)으로 스캔해 걸리면 omitted(content=null, size_bytes=디코드 길이),
  아니면 그대로 둔다. 스캔·판정 로직(`_finds_secret`)은 마스커 자체 구현이다 — 엔진 ③의 `scan_text`를 쓰지 않는다.
  독립성의 실체는 이 판정 로직이다. base64 디코드·퍼센트 디코드 자체는 표준 라이브러리라 양쪽이 같다(독립 아님 — 정직 표기).
  변형 범위는 ③과 같게 맞춘다: utf-8(errors=replace) 텍스트 + '%'·'+'가 있으면 퍼센트(+) 디코드 변형.
  변형 규칙은 '언제 어떤 표준 함수를 부르나'라 데이터로 빼지 않았다 — 같은 변형을 본다는 것은 동등성 테스트가 고정한다.
- size_bytes는 마스킹 뒤 content로 산출, truncated=false(절단하지 않음 — §2.2 절단은 마스킹 뒤).

독립성(`masker_independence`, R-11): 엔진 검증 파이프라인(`sentinel.pipeline`)을 쓰지 않는다. 엔진의 공용 정의
(`schema`·`common_types`·`strict_json`·정책 데이터)는 쓴다 — 검증 로직이 아니다.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import unquote_plus

from pydantic import ValidationError

from sentinel import strict_json
from sentinel.common_types import FILLER
from sentinel.sanitization_policy import DEFAULT_POLICY, PATTERNS
from sentinel.schema import Envelope
from tools.fixture_masker.raw import RAW_SCHEMA_VERSION, RawBody, RawEnvelope, RawHeader, RawTransaction

log = logging.getLogger("fixture_masker")

Mode = Literal["strict_redaction", "relation_preserving"]
MODES: Final = ("strict_redaction", "relation_preserving")
REPO_ROOT: Final = Path(__file__).resolve().parents[2]
POLICY: Final = DEFAULT_POLICY
FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"
MAX_LABEL: Final = 9999  # MaskLabel = ref_ + 숫자 2~4자리
# 유출 검사가 값 전체와 함께 찾는 비밀 구성요소의 최소 길이(짧은 조각은 오탐 — 마스커-A와 같은 기준)
MIN_FRAGMENT: Final = 8

REASON_CODES: Final = (
    "input_inside_repo",      # 원본 입력 경로가 레포 안
    "input_unreadable",
    "input_not_json",         # UTF-8·엄격 JSON(§2.6 정의)이 아님
    "unknown_schema_version",
    "raw_schema_invalid",     # RawEnvelope 위반(마스킹 산출물 필드 혼입 포함)
    "unknown_mode",
    "policy_matcher_unknown", # body_rules matcher가 json:/form: 문법이 아님
    "body_unparseable",       # JSON이라고 선언했는데 엄격 JSON이 아님 — 비밀 위치를 찾을 수 없다(fail-closed)
    "transform_failed",
    "label_space_exhausted",
    "span_invariant_violated",  # 출력 masked_spans가 Body 불변식 1~6을 어김
    "label_rule_violated",      # strict인데 라벨 / relation인데 원본값 ↔ 라벨이 일대일이 아님
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


def _body_globs() -> dict[str, list[str]]:
    globs: dict[str, list[str]] = {"json": [], "form": []}
    for rule in POLICY.body_rules:
        kind, sep, pattern = rule.matcher.partition(":")
        if not sep or kind not in globs or not pattern:
            raise MaskerRejected("policy_matcher_unknown")
        if rule.action != "keep":  # redact·pseudonymize는 지금 같은 처리(FILLER + span) — 차이는 미정(큐)
            globs[kind].append(pattern.lower())
    return globs


def _matches(name: str, globs: list[str]) -> bool:
    return any(fnmatchcase(name.lower(), g) for g in globs)


# ── 실행 상태: HMAC 키·매핑 테이블 ───────────────────────────────────

class _Run:
    """한 번의 실행 상태. 키·매핑 테이블·원본 값은 이 실행 안에서만 쓰고 `discard`로 버린다."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.key: bytes | None = secrets.token_bytes(32)  # 실행마다 새 키 — 저장·출력하지 않는다
        self.table: dict[bytes, str] = {}                # HMAC(키, 원본값) → 라벨
        self.emitted: list[tuple[bytes, str | None]] = []  # 출력한 MaskedRef마다 (HMAC, 라벨) — 자체 검증용
        self.originals: list[str] = []                   # 유출 검사용
        self.hosts = 0
        self.count = 0

    def _digest(self, original: str) -> bytes:
        return hmac.new(self.key, original.encode("utf-8"), hashlib.sha256).digest()

    def _label(self, digest: bytes) -> str | None:
        if self.mode == "strict_redaction":
            return None  # (A) §2.3: strict_redaction → label=null
        if digest not in self.table:
            n = len(self.table) + 1
            if n > MAX_LABEL:
                raise MaskerRejected("label_space_exhausted")
            self.table[digest] = f"ref_{n:02d}"  # 순번 할당 — 해시를 잘라 쓰지 않는다
        return self.table[digest]

    def masked(self, original: str, kind: str) -> dict[str, Any]:
        self.originals.append(original)
        digest = self._digest(original)
        label = self._label(digest)
        self.emitted.append((digest, label))
        self.count += 1
        return {"masked": True, "label": label, "kind": kind}

    def discard(self) -> None:
        self.key = None
        self.table.clear()
        self.emitted.clear()
        self.originals.clear()


# ── 변환 ──────────────────────────────────────────────────────────

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


def _is_form(b: RawBody) -> bool:
    return b.content_type.split(";", 1)[0].strip().lower() == FORM_CONTENT_TYPE


def _declares_json(b: RawBody) -> bool:
    return "json" in b.content_type.split(";", 1)[0].strip().lower()


def _mask_json(content: str, globs: list[str], run: _Run) -> tuple[str, list[dict]]:
    if not globs:
        return content, []
    hits = [(p, s, e) for p, key, s, e in strict_json.string_value_spans(content)
            if key is not None and _matches(key, globs)]
    spans = []
    for pointer, start, end in hits:  # 문서 순서로 라벨 발급(결정론적)
        spans.append({"at": {"kind": "json", "path": pointer},
                      "ref": run.masked(json.loads(content[start:end]), "token")})
    for _pointer, start, end in reversed(hits):  # 뒤에서부터 제자리 치환(앞 오프셋 보존)
        content = content[:start] + json.dumps(FILLER) + content[end:]
    return content, sorted(spans, key=lambda s: s["at"]["path"])


def _mask_form(content: str, globs: list[str], run: _Run) -> tuple[str, list[dict]]:
    parts, spans, offset = [], [], 0
    for pair in content.split("&"):
        raw_name, sep, raw_value = pair.partition("=")
        name = unquote_plus(raw_name)
        if sep and raw_value and _matches(name, globs):
            ref = run.masked(unquote_plus(raw_value), "token")
            run.originals.append(raw_value)  # 인코딩된 형태도 유출 검사 대상
            start = offset + len(raw_name) + 1
            spans.append({"at": {"kind": "text", "range": {"start": start, "end": start + len(FILLER)}}, "ref": ref})
            pair = f"{raw_name}={FILLER}"
        parts.append(pair)
        offset += len(pair) + 1
    return "&".join(parts), spans


def _body(b: RawBody, run: _Run, globs: dict[str, list[str]]) -> dict[str, Any]:
    content, spans = b.content, []
    if b.encoding == "utf8" and content is not None:
        try:
            strict_json.parse(content)
            doc_ok = True
        except ValueError:
            doc_ok = False
        if doc_ok:
            content, spans = _mask_json(content, globs["json"], run)
        elif _is_form(b):
            content, spans = _mask_form(content, globs["form"], run)
        elif _declares_json(b):
            raise MaskerRejected("body_unparseable")
    if b.encoding == "base64" and content is not None:
        decoded = base64.b64decode(content, validate=True)  # 디코드 불가 → transform_failed
        if _finds_secret(decoded.decode("utf-8", errors="replace")):  # 디코드 바이트는 이 함수 밖으로 나가지 않는다
            return {"content_type": b.content_type, "size_bytes": len(decoded), "truncated": False,
                    "encoding": "omitted", "content": None, "masked_spans": []}  # (A) §2.2 불변식 2'
        return {"content_type": b.content_type, "size_bytes": len(decoded), "truncated": False, "encoding": "base64",
                "content": content, "masked_spans": []}
    if b.encoding == "omitted" or content is None:
        size = 0
    else:
        size = len(content.encode("utf-8"))
    return {"content_type": b.content_type, "size_bytes": size, "truncated": False, "encoding": b.encoding,
            "content": None if b.encoding == "omitted" else content, "masked_spans": spans}


def _finds_secret(text: str) -> bool:
    """정책 패턴이 text(또는 그 퍼센트(+) 디코드 변형)에서 하나라도 걸리는가 — 마스커 자체 판정(엔진 ③과 독립 구현)."""
    variants = [text, unquote_plus(text)] if ("%" in text or "+" in text) else [text]
    return any(pattern.search(v) for v in variants for pattern in PATTERNS.values())


def _transaction(tx: RawTransaction, run: _Run, globs: dict[str, list[str]]) -> dict[str, Any]:
    start = run.count
    req, resp = tx.request, tx.response
    run.originals.append(req.host)
    run.hosts += 1
    headers = [_header(h, run) for h in req.headers]
    req_body = _body(req.body, run, globs)
    params = [{"name": p.name, "location": p.location,
               "value": run.masked(p.value, "token") if p.location == "form" and _matches(p.name, globs["form"])
               else p.value}
              for p in req.query_params]
    resp_headers = [_header(h, run) for h in resp.headers]
    resp_body = _body(resp.body, run, globs)
    out = {
        "meta": {"transaction_id": str(tx.meta.transaction_id), "captured_at": tx.meta.captured_at.isoformat(),
                 "origin_ref": tx.meta.origin_ref, "sanitization": None},
        "request": {"method": req.method, "scheme": req.scheme, "host": f"masked-host-{run.hosts:02d}.invalid",
                    "port": req.port, "path": req.path, "query_params": params, "headers": headers, "body": req_body},
        "response": {"status": resp.status, "headers": resp_headers, "body": resp_body, "elapsed_ms": resp.elapsed_ms},
    }
    refs = [h["value"] for h in headers + resp_headers if isinstance(h["value"], dict)]
    refs += [p["value"] for p in params if isinstance(p["value"], dict)]
    refs += [s["ref"] for b in (req_body, resp_body) for s in b["masked_spans"]]
    kinds = {"token": 0, "cookie": 0, "pii": 0, "host": 0}
    for ref in refs:
        kinds[ref["kind"]] += 1
    out["meta"]["sanitization"] = {"applied": True, "failed": False, "policy_version": POLICY.policy_version,
                                   "redacted_count": run.count - start, "redacted_kinds": kinds}
    return out


# ── 출력 전 자체 검증(엔진 ③과 독립) ─────────────────────────────────

def _span_key(at: dict) -> tuple[str, str, int]:
    return (at["kind"], at.get("path", ""), at["range"]["start"] if at.get("range") else -1)


def _spans_ok(body: dict) -> bool:
    """Body 불변식 1~6((A) §2.2). 엔진 ③과 같은 규칙을 마스커가 따로 구현한다(R-11 — 같은 코드를 공유하지 않음)."""
    spans = body["masked_spans"]
    if not spans:
        return True
    content = body["content"]
    if body["encoding"] != "utf8" or content is None:                                       # 1
        return False
    doc = None
    for s in spans:
        at, rng = s["at"], s["at"].get("range")
        if at["kind"] == "text":
            if rng is None:                                                                  # 2
                return False
            value = content
        else:
            if doc is None:
                try:
                    doc = strict_json.parse(content)                                         # 4
                except ValueError:
                    return False
            found, value = strict_json.resolve(doc, at["path"])
            if not found:
                return False
        if not isinstance(value, str):                                                       # 3
            return False
        if rng is None and value != FILLER:
            return False
        if rng is not None and (rng["end"] - rng["start"] != len(FILLER) or value[rng["start"]:rng["end"]] != FILLER):
            return False
    groups: dict[tuple, list] = {}
    for s in spans:                                                                          # 5(같은 kind 안)
        groups.setdefault((s["at"]["kind"], s["at"].get("path", "")), []).append(s["at"].get("range"))
    for ranges in groups.values():
        if len(ranges) > 1 and None in ranges:
            return False
        bounded = sorted((r["start"], r["end"]) for r in ranges if r)
        if any(b[0] < a[1] for a, b in zip(bounded, bounded[1:])):
            return False
    keys = [_span_key(s["at"]) for s in spans]                                               # 6
    return keys == sorted(keys)


def _labels_ok(run: _Run) -> bool:
    if run.mode == "strict_redaction":
        return all(label is None for _, label in run.emitted)
    by_digest: dict[bytes, str | None] = {}
    by_label: dict[str | None, bytes] = {}
    for digest, label in run.emitted:  # 원본값(HMAC) ↔ 라벨 양방향 일대일
        if label is None or by_digest.setdefault(digest, label) != label or by_label.setdefault(label, digest) != digest:
            return False
    return True


def _string_leaves(node: Any):
    if isinstance(node, dict):
        for v in node.values():
            yield from _string_leaves(v)
    elif isinstance(node, list):
        for v in node:
            yield from _string_leaves(v)
    elif isinstance(node, str):
        yield node


def _secret_parts(value: str) -> list[str]:
    """헤더 값 안의 비밀 구성요소: `이름=값` 쌍의 값, `스킴 자격증명`의 자격증명. 이름·스킴은 비밀이 아니다."""
    parts = []
    for segment in re.split(r"[;,]", value):
        segment = segment.strip()
        if "=" in segment:
            parts.append(segment.split("=", 1)[1].strip())
        else:
            words = segment.split()
            parts += words[1:] if len(words) > 1 else words
    return parts


def _needles(originals: list[str]) -> set[str]:
    found = {o for o in originals if o}
    for o in originals:
        found.update(p for p in _secret_parts(o) if len(p) >= MIN_FRAGMENT)
    return found


def _leaked(serialized: list[str], originals: list[str]) -> bool:
    """마스킹한 원본 값(또는 그 비밀 구성요소)이 출력 문자열 어디에든 남았는가. 파싱한 값에서 본다(이스케이프 무관)."""
    needles = _needles(originals)
    return any(n in leaf for text in serialized for leaf in _string_leaves(json.loads(text)) for n in needles)


def mask(raw: RawEnvelope, mode: str = "strict_redaction") -> list[tuple[str, bytes]]:
    """(파일 이름, 마스킹된 Envelope 바이트) 목록. 자체 검증을 모두 통과한 것만 돌려준다."""
    if mode not in MODES:
        raise MaskerRejected("unknown_mode")
    globs = _body_globs()
    run = _Run(mode)
    try:
        try:
            drafts = [_transaction(tx, run, globs) for tx in raw.transactions]
        except MaskerRejected:
            raise
        except Exception:
            raise MaskerRejected("transform_failed") from None  # 원 예외 메시지에 원본 조각이 있을 수 있다 — 체인을 끊는다
        if not all(_spans_ok(d[side]["body"]) for d in drafts for side in ("request", "response")):
            raise MaskerRejected("span_invariant_violated")
        if not _labels_ok(run):
            raise MaskerRejected("label_rule_violated")
        try:
            envelopes = [Envelope.model_validate_json(json.dumps(
                {"schema_version": "1.0", "analysis_type": "single", "transactions": [d]}, ensure_ascii=False))
                for d in drafts]
        except ValidationError:
            raise MaskerRejected("output_build_failed") from None
        serialized = [e.model_dump_json() for e in envelopes]
        if _leaked(serialized, run.originals):
            raise MaskerRejected("masked_value_leaked")
        return [(f"{e.transactions[0].meta.transaction_id}.json", s.encode("utf-8"))
                for e, s in zip(envelopes, serialized)]
    finally:
        run.discard()  # 성공·실패와 무관하게 키·매핑 테이블·원본 값을 버린다


# ── 출력 ──────────────────────────────────────────────────────────

def run(raw_path: Path, out_dir: Path, mode: str = "strict_redaction") -> int:
    """원본 파일 → out_dir에 트랜잭션마다 Envelope 하나. 전부 만든 뒤에만 쓴다(부분 출력 없음)."""
    outputs = mask(load_raw(raw_path), mode)
    out_dir = Path(out_dir)
    if any((out_dir / name).exists() for name, _ in outputs):
        raise MaskerRejected("output_exists")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in outputs:
        (out_dir / name).write_bytes(data)
    log.info("masked transactions=%d", len(outputs))
    return len(outputs)
