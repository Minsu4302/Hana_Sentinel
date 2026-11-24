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
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

from sentinel import strict_json


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


class ObjectIdRule(_Strict):
    matcher: str  # (A) §2.3 — query:/form:/json: 이름 glob
    action: Literal["pseudonymize"]


class SanitizationPolicy(_Strict):
    policy_version: str
    mode: Literal["strict_redaction", "relation_preserving"] = "strict_redaction"
    header_rules: tuple[HeaderRule, ...]
    body_rules: tuple[BodyRule, ...] = ()
    object_id_policy: Literal["pseudonymize_if_sensitive", "keep"] = "pseudonymize_if_sensitive"
    object_id_rules: tuple[ObjectIdRule, ...] = ()

    def requires_masked_header(self, name: str) -> bool:
        lowered = name.lower()
        return any(fnmatchcase(lowered, r.name_pattern.lower()) and r.action != "keep" for r in self.header_rules)


# 정책 값의 정본은 데이터 파일 하나다((A) §2.3 — Python이 읽고, Java는 같은 파일을 빌드 리소스로 넣는다).
# 이 모듈은 구조(모델)와 로더만 둔다. 규칙 값을 코드에 다시 적지 않는다. PATTERNS는 ③ 전용이라 파일에 없다.
POLICY_PATH: Final = Path(__file__).with_name("sanitization_policy.json")


def load_policy(path: Path = POLICY_PATH) -> SanitizationPolicy:
    """정책 파일 → SanitizationPolicy. 엄격 JSON(중복 키·NaN 거부)이 아니거나 구조가 틀리면 예외(기동 거부)."""
    text = Path(path).read_text(encoding="utf-8")
    strict_json.parse(text)
    return SanitizationPolicy.model_validate_json(text)


DEFAULT_POLICY: Final = load_policy()
