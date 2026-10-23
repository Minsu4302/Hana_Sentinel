"""파이프라인 ③ Sanitization 독립 재검증 — (A) §2.3 신뢰 경계, §3.0 ③, §3.6.

`applied==true`는 요청자가 쓰는 주장일 뿐이다. 여기서는 마스킹됐다는 주장을 믿지 않고 데이터를 스스로
재검증한다:
- **주 방어선 — 값 기반 재스캔**: Envelope의 모든 문자열(헤더·파라미터의 이름과 값, 경로, 본문, 메타)과
  base64 본문의 디코드 결과, 퍼센트 디코드 결과를 아래 PATTERNS로 스캔한다. 하나라도 걸리면 `applied`
  값과 무관하게 거부(영수증 ≠ 데이터면 데이터를 믿고 거부).
- **fail-closed**: `applied`가 true가 아니거나 `failed`가 true면 데이터가 깨끗해 보여도 거부. 영수증 필드
  누락·타입 오류는 ② 스키마에서 이미 거부된다.
- **보조 — 이름 화이트리스트**: 정책 `header_rules` 대상 헤더가 평문이면 거부.
- **본문 계약**: `omitted`인데 content가 있음, base64 디코드 불가, 내용 상한 초과((A) §2.2 req 64KB /
  resp 256KB) → 거부.

한계((A) §2.3 그대로): 패턴 검사는 '정책에 정의된 패턴'만 탐지하며 '모든 비밀값 부재'를 증명하지 않는다
(불투명 세션 ID는 일반 문자열과 구분 불가). 이 재검증(Python, 2차 방어선)은 Java의 전송 전 마스킹(1차)을
대체하지 않는다.
감사에는 사유 코드·패턴 이름·구조 위치(스키마 필드명과 인덱스)만 남기고, 값·입력이 정한 이름은 남기지 않는다.
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
from typing import Any, Final
from urllib.parse import unquote_plus

from sentinel.sanitization_policy import DEFAULT_POLICY, SanitizationPolicy
from sentinel.schema import Body, Envelope, Transaction

audit_log = logging.getLogger("sentinel.audit")

REQ_BODY_CAP: Final = 64 * 1024  # (A) §2.2 config화 대상 — 현재 기본값
RESP_BODY_CAP: Final = 256 * 1024

_CRED_NAMES = r"(?:password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|id_token|auth_token|token)"
_SESSION_NAMES = (r"(?:jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|sessionid|session|sid|token|auth|"
                  r"access_token|refresh_token|id_token|csrftoken|xsrf-token)")

# 정책에 정의된 패턴(이것만 탐지한다). 패턴 이름만 감사에 남는다.
PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "auth_scheme_credential": re.compile(r"(?i)\b(?:bearer|basic|digest|negotiate|ntlm)\s+[A-Za-z0-9._~+/=-]{8,}"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "api_secret_key": re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35})\b"),
    "session_cookie_pair": re.compile(rf"(?i)(?:^|[\s;&?/]){_SESSION_NAMES}=[^;\s&/]{{8,}}"),  # '/'·';' = URL 재작성 세션
    "credential_json_field": re.compile(rf'(?i)"{_CRED_NAMES}"\s*:\s*"[^"]+"'),
    "credential_form_field": re.compile(rf"(?i)(?:^|[&?]){_CRED_NAMES}=[^&\s]+"),
}


class SanitizationRejected(ValueError):
    """재검증 거부. 값을 담지 않는다(사유 코드·위치만)."""

    def __init__(self, reasons: tuple[str, ...]):
        self.reasons = reasons
        super().__init__(f"sanitization_rejected reasons={len(reasons)}")


def scan_text(text: str) -> list[str]:
    """문자열(과 퍼센트 디코드 결과)에서 걸린 패턴 이름들."""
    variants = {text}
    if "%" in text or "+" in text:
        variants.add(unquote_plus(text))
    return sorted({name for v in variants for name, p in PATTERNS.items() if p.search(v)})


def _walk_strings(node: Any, where: str):
    """모델 덤프의 모든 문자열 잎을 (위치, 값)으로. MaskedRef는 값이 아니라 마스킹 표지라 건너뛴다."""
    if isinstance(node, dict):
        if node.get("masked") is True and set(node) == {"masked", "label", "kind"}:
            return
        for key, value in node.items():
            yield from _walk_strings(value, f"{where}.{key}")
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            yield from _walk_strings(value, f"{where}[{i}]")
    elif isinstance(node, str):
        yield where, node


def body_bytes(body: Body) -> bytes | None:
    """본문 내용을 바이트로. base64 디코드 불가는 ValueError(재검증 불가 → 거부)."""
    if body.content is None:
        return None
    if body.encoding == "base64":
        try:
            return base64.b64decode(body.content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("undecodable_base64") from exc
    return body.content.encode("utf-8")


def check_body(body: Body, where: str, cap: int) -> list[str]:
    if body.encoding == "omitted":
        return [f"omitted_with_content@{where}"] if body.content is not None else []
    try:
        data = body_bytes(body)
    except ValueError:
        return [f"undecodable_base64@{where}"]
    if data is None:
        return []
    found = [f"body_over_cap@{where}"] if len(data) > cap else []
    if body.encoding == "base64":  # 디코드 결과도 재스캔(인코딩으로 숨긴 생문자열)
        found += [f"{p}@{where}.decoded" for p in scan_text(data.decode("utf-8", errors="replace"))]
    return found


def check_transaction(tx: Transaction, where: str, policy: SanitizationPolicy) -> list[str]:
    receipt = tx.meta.sanitization
    found: list[str] = []
    if receipt.applied is not True:
        found.append(f"receipt_not_applied@{where}.meta")
    if receipt.failed is not False:
        found.append(f"receipt_failed@{where}.meta")
    found += check_body(tx.request.body, f"{where}.request.body", REQ_BODY_CAP)
    found += check_body(tx.response.body, f"{where}.response.body", RESP_BODY_CAP)
    for side, headers in (("request", tx.request.headers), ("response", tx.response.headers)):
        for i, h in enumerate(headers):
            if isinstance(h.value, str) and policy.requires_masked_header(h.name):
                found.append(f"plaintext_sensitive_header@{where}.{side}.headers[{i}]")
    for loc, text in _walk_strings(tx.model_dump(mode="python"), where):
        found += [f"{p}@{loc}" for p in scan_text(text)]
    return found


def verify_sanitization(envelope: Envelope, policy: SanitizationPolicy = DEFAULT_POLICY) -> None:
    reasons: list[str] = []
    for i, tx in enumerate(envelope.transactions):
        reasons += check_transaction(tx, f"tx{i}", policy)
    if reasons:
        unique = tuple(sorted(set(reasons)))
        audit_log.warning("sanitization_rejected count=%d reasons=%s", len(unique), ",".join(unique))
        raise SanitizationRejected(unique)
