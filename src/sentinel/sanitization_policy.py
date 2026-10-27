"""SanitizationPolicy — (A) §2.3 구조. 값은 정본 FROZEN이 아니라 설정값이다(W1-05 리뷰 결정).

파이프라인 ③에서 이 정책의 `header_rules`는 **보조** 방어선으로만 쓴다: action이 redact/pseudonymize인
헤더가 평문으로 오면 거부. 주 방어선은 값 기반 재스캔(`sentinel.pipeline.sanitization_check`)이며,
이 목록 밖 헤더의 평문 비밀값도 그쪽이 잡아야 한다.

`PATTERNS`는 '무엇을 찾나'의 정책 데이터다((A) §2.3 "정책에 정의된 패턴"). 엔진 ③(`sanitization_check`)과 fixture
마스커가 같은 목록을 쓰되, 그 목록으로 스캔·판정하는 로직은 각자 따로 구현한다(R-11 — 같은 코드를 공유하지 않음).
"""
from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict


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
    # 본문 규칙((A) §2.3 matcher 문법): json:<키 glob> = 모든 깊이의 이름 일치 멤버 중 문자열 값 노드 /
    # form:<이름 glob> = 폼 본문 파라미터 값. 대소문자 무시. 소비자는 fixture 마스커(와 미래 Java) — ③은 쓰지 않는다.
    body_rules=tuple(BodyRule(matcher=f"{kind}:{p}", action="redact") for kind in ("json", "form") for p in (
        "password", "passwd", "pwd", "*token*", "*secret*", "*session*", "*api*key*", "*apikey*",
    )),
)
