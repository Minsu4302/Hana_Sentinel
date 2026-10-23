"""파이프라인 ② 스키마 검증 — 원시 본문 → Envelope.

거부 시 감사에는 오류 *유형*과 개수만 남긴다. Pydantic 오류 메시지·위치(loc)에는 입력 값과
입력이 정한 필드명이 들어갈 수 있으므로 기록·반사하지 않는다(예외 체인도 끊는다).
"""
from __future__ import annotations

import logging

from pydantic import ValidationError

from sentinel.schema import Envelope

audit_log = logging.getLogger("sentinel.audit")


class SchemaRejected(ValueError):
    """스키마 위반 — 거부. 입력 값을 담지 않는다."""

    def __init__(self, error_types: tuple[str, ...]):
        self.error_types = error_types
        super().__init__(f"schema_rejected types={','.join(error_types)}")


def parse_envelope(raw: bytes) -> Envelope:
    try:
        return Envelope.model_validate_json(raw)
    except ValidationError as exc:
        types = tuple(sorted({e["type"] for e in exc.errors(include_input=False, include_url=False)}))
        audit_log.warning("schema_rejected errors=%d types=%s", exc.error_count(), ",".join(types))
        raise SchemaRejected(types) from None
