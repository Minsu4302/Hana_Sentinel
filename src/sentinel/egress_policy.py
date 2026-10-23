"""egress 정책 — 외부 egress 허용목록(빈 값)과 목적지 분류.

(A) §3.1 `egress_static_check` · `local_llm_vs_egress` / §1.3 ⓑ(N1).
이 모듈은 송신하지 않는다(소켓·HTTP import 없음 — W1-01 경계 검사 대상). '어디로 가면 egress인가'의
판정만 정의하며, 테스트 환경의 런타임 차단 가드도 같은 판정을 쓴다.

개념 분리:
- **로컬 LLM 엔드포인트**: 루프백 주소. 같은 PC 안이므로 외부 egress가 아니다 → 허용목록 항목이 아니라
  분류(LOCAL)로 다룬다.
- **외부 egress**: 루프백이 아닌 모든 목적지. 허용목록(EGRESS_ALLOWLIST)에 있어야만 허용되며,
  허용목록은 비어 있다 — 상용 AI API·인터넷은 물론, 사내 주소도 승인 개념이 정해지기 전(4번 주제)까지는 egress로 취급.
판정이 애매하면(해석 불가 호스트, IPv4-mapped 등) 외부로 분류한다(fail-closed).
"""
from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Final

# 외부 egress 허용 목적지. 비어 있어야 한다(불변 tuple). 항목 추가는 (A) 정본 변경 사항이다.
EGRESS_ALLOWLIST: Final[tuple[str, ...]] = ()

_LOOPBACK_NAMES: Final = frozenset({"localhost"})


class Destination(Enum):
    LOCAL = "local"  # 루프백 — 로컬 LLM 엔드포인트가 놓일 수 있는 유일한 곳
    EXTERNAL = "external"  # 외부 egress


def classify_destination(host: str | bytes | None) -> Destination:
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return Destination.EXTERNAL
    if not host:
        return Destination.EXTERNAL
    name = host.strip().strip("[]").lower()
    if name in _LOOPBACK_NAMES:
        return Destination.LOCAL
    try:
        addr = ipaddress.ip_address(name.split("%", 1)[0])  # IPv6 zone id 제거
    except ValueError:
        return Destination.EXTERNAL  # 이름(DNS 필요) 또는 해석 불가 → 외부
    return Destination.LOCAL if addr.is_loopback else Destination.EXTERNAL


def is_external_egress_permitted(host: str) -> bool:
    """외부 egress 허용 여부. 루프백은 egress가 아니므로 여기서 다루지 않는다."""
    return classify_destination(host) is Destination.EXTERNAL and host in EGRESS_ALLOWLIST
