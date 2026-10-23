"""SanitizationPolicy — (A) §2.3 구조. 값은 정본 FROZEN이 아니라 설정값이다(W1-05 리뷰 결정).

파이프라인 ③에서 이 정책의 `header_rules`는 **보조** 방어선으로만 쓴다: action이 redact/pseudonymize인
헤더가 평문으로 오면 거부. 주 방어선은 값 기반 재스캔(`sentinel.pipeline.sanitization_check`)이며,
이 목록 밖 헤더의 평문 비밀값도 그쪽이 잡아야 한다.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Literal

from pydantic import BaseModel, ConfigDict


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class HeaderRule(_Strict):
    name_pattern: str  # 대소문자 무시 glob(예: "cookie", "*token*")
    action: Literal["redact", "pseudonymize", "keep"]


class BodyRule(_Strict):
    matcher: str
    action: Literal["redact", "pseudonymize", "keep"]


class SanitizationPolicy(_Strict):
    policy_version: str
    mode: Literal["strict_redaction", "relation_preserving"] = "strict_redaction"
    header_rules: tuple[HeaderRule, ...]
    body_rules: tuple[BodyRule, ...] = ()
    object_id_policy: Literal["pseudonymize_if_sensitive", "keep"] = "pseudonymize_if_sensitive"

    def requires_masked_header(self, name: str) -> bool:
        lowered = name.lower()
        return any(fnmatchcase(lowered, r.name_pattern.lower()) and r.action != "keep" for r in self.header_rules)


# 초기 설정값(정본 결정 아님). 인증·세션·키를 실어 나르는 대표 헤더.
DEFAULT_POLICY = SanitizationPolicy(
    policy_version="python-recheck-1",
    header_rules=tuple(HeaderRule(name_pattern=p, action="redact") for p in (
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "*api-key*", "*apikey*", "*token*", "*secret*", "*session*",
    )),
)
