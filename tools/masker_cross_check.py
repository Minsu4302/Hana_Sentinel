"""마스커 출력 ↔ 엔진 교차 검증 — 마스킹된 Envelope 바이트를 엔진의 실제 ②③ 경로에 넣어 판정을 돌려준다.

교차 검증이지 순환이 아닌 이유: 마스커(`tools/fixture_masker`)는 엔진 검증 파이프라인을 import하지 않는다
(`masker_independence`). 마스킹(생산)과 재검증(③)은 같은 정책 데이터(`sanitization_policy`)를 보되 서로 다른 코드다.
두 독립 구현이 같은 결론에 이르는 것이 교차 검증이다. 이 모듈은 그 판정 쪽만 부른다 — 마스커 패키지 밖에 두는 이유
(마스커는 이 모듈을 import하지 않는다).

①(토큰)은 대상이 아니다 — 마스커 출력에는 도구 토큰이 없다. ②(`schema_gate.parse_envelope`)와
③(`sanitization_check.verify_sanitization` — 값 재스캔 + masked_span_integrity)만 부른다.
"""
from __future__ import annotations

from sentinel.pipeline import sanitization_check, schema_gate


def engine_verdict(envelope_bytes: bytes) -> tuple[str, tuple[str, ...]]:
    """("accepted", ()) | ("schema_rejected", 오류 유형) | ("sanitization_rejected", 사유 코드)."""
    try:
        envelope = schema_gate.parse_envelope(envelope_bytes)
    except schema_gate.SchemaRejected as exc:
        return "schema_rejected", exc.error_types
    try:
        sanitization_check.verify_sanitization(envelope)
    except sanitization_check.SanitizationRejected as exc:
        return "sanitization_rejected", tuple(sorted({r.split("@")[0] for r in exc.reasons}))
    return "accepted", ()
