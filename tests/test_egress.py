"""egress 경계 — `egress_static_check` · `egress_runtime_block`(테스트환경 한정) · `local_llm_vs_egress`.

'위조 거부'로 증명한다: 송신 의존성을 심으면 검출, 비어 있지 않은 허용목록 거부, 외부 목적지 시도는
가드가 차단하고 그 실패가 가드에 귀속됨(네트워크 부재로 우연히 실패한 것이 아님)을 이벤트로 확인.
외부 프로브 주소는 RFC 5737 TEST-NET(192.0.2.0/24)과 예약 도메인(.invalid/.example)만 쓴다.
"""
from __future__ import annotations

import socket
import urllib.error
import urllib.request

import pytest

import sentinel.egress_policy as policy
from sentinel.egress_policy import Destination, classify_destination, is_external_egress_permitted
from tools.dep_egress import (
    EGRESS_DISTRIBUTIONS, DependencyScanError, declared_dependencies, find_egress_dependencies)
from tools.egress_guard import EgressBlocked, EgressGuard
from tools.guardrails import REPO_ROOT

TEST_NET = "192.0.2.1"  # RFC 5737 — 문서용, 라우팅되지 않음


def _fake_index(index: dict[str, list[str]]):
    return lambda name: index.get(name)


# ── (a) 정적: 제품 런타임 의존성(전이 포함) ───────────────────────────

def test_product_runtime_dependencies_have_no_egress_library():
    declared = declared_dependencies(REPO_ROOT / "pyproject.toml")
    assert find_egress_dependencies(declared) == []


@pytest.mark.parametrize("declared", [["requests>=2"], ["HTTPX"], ["openai==1.0"], ["anthropic"],
                                      ["Requests_OAuthlib", "urllib3"]])
def test_rejects_planted_direct_egress_dependency(declared):
    index = {"requests-oauthlib": []}
    found = find_egress_dependencies(declared, _fake_index(index))
    assert found and all(f.name in EGRESS_DISTRIBUTIONS for f in found)


def test_rejects_egress_library_reached_transitively():
    index = {"innocent-sdk": ["helper>=1"], "helper": ["httpx>=0.27"]}
    found = find_egress_dependencies(["innocent-sdk"], _fake_index(index))
    assert [(f.name, f.chain) for f in found] == [("httpx", ("innocent-sdk", "helper", "httpx"))]


def test_rejects_egress_library_pulled_in_by_requested_extra():
    index = {"webframework": ['starlette', 'httpx ; extra == "client"'], "starlette": []}
    assert find_egress_dependencies(["webframework"], _fake_index(index)) == []  # 대조군: extra 미요청
    found = find_egress_dependencies(["webframework[client]"], _fake_index(index))
    assert [f.name for f in found] == ["httpx"]


def test_unresolvable_dependency_is_an_error_not_a_pass():
    with pytest.raises(DependencyScanError, match="메타데이터 없음"):
        find_egress_dependencies(["not-installed-anywhere"], _fake_index({}))
    with pytest.raises(DependencyScanError, match="해석 불가"):
        find_egress_dependencies(["!!not a requirement"], _fake_index({}))


def test_egress_allowlist_is_empty_and_immutable():
    assert policy.EGRESS_ALLOWLIST == ()
    assert isinstance(policy.EGRESS_ALLOWLIST, tuple)


def test_non_empty_allowlist_would_permit_egress_so_it_must_stay_empty(monkeypatch):
    """허용목록이 실제로 egress 허용 판정에 쓰임을 보여, '빈 값' 검사가 장식이 아님을 증명."""
    assert not is_external_egress_permitted("api.example")
    monkeypatch.setattr(policy, "EGRESS_ALLOWLIST", ("api.example",))
    assert is_external_egress_permitted("api.example")


# ── (c) 로컬 LLM 엔드포인트(루프백) ≠ 외부 egress ─────────────────────

@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost", "LOCALHOST",
                                  b"127.0.0.1"])
def test_loopback_is_local_not_egress(host):
    assert classify_destination(host) is Destination.LOCAL


@pytest.mark.parametrize("host", [
    "api.openai.example", "api.anthropic.example", "8.8.8.8", TEST_NET,
    "10.0.0.5", "192.168.0.10",  # 사내 대역도 승인 개념(4번 주제) 전에는 egress
    "0.0.0.0", "localhost.attacker.example", "127.0.0.1.nip.example", "0x7f.1",
    "::ffff:127.0.0.1", "", None, b"\xff\xfe",
])
def test_non_loopback_or_disguised_hosts_are_external(host):
    assert classify_destination(host) is Destination.EXTERNAL


def test_local_llm_endpoint_needs_no_allowlist_entry():
    """로컬은 분류로 허용되고 허용목록을 쓰지 않는다 → 허용목록은 비어 있는 채로 유지된다."""
    assert classify_destination("127.0.0.1") is Destination.LOCAL
    assert not is_external_egress_permitted("127.0.0.1")
    assert policy.EGRESS_ALLOWLIST == ()


# ── (b) 런타임: 테스트 환경 egress 차단 실증 ───────────────────────────

def test_guard_is_installed_for_the_whole_test_session(egress_guard):
    assert egress_guard.installed
    assert socket.getaddrinfo.__qualname__.startswith("EgressGuard.install")


def test_external_tcp_connect_is_blocked_and_attributed_to_guard(egress_guard):
    with egress_guard.probe(), pytest.raises(EgressBlocked):
        socket.create_connection((TEST_NET, 80), timeout=1)
    assert egress_guard.events and all(e.probe and e.host == TEST_NET for e in egress_guard.events)


def test_external_raw_socket_connect_is_blocked(egress_guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with egress_guard.probe():
            with pytest.raises(EgressBlocked):
                s.connect((TEST_NET, 443))
            with pytest.raises(EgressBlocked):
                s.connect_ex((TEST_NET, 443))
    finally:
        s.close()
    assert [e.op for e in egress_guard.events] == ["connect", "connect"]


def test_external_dns_resolution_is_blocked(egress_guard):
    with egress_guard.probe(), pytest.raises(EgressBlocked):
        socket.getaddrinfo("egress-probe.invalid", 443)
    assert egress_guard.events[-1].op == "resolve"


def test_external_udp_sendto_is_blocked(egress_guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with egress_guard.probe(), pytest.raises(EgressBlocked):
            s.sendto(b"probe", (TEST_NET, 53))
    finally:
        s.close()
    assert egress_guard.events[-1].op == "sendto"


def test_urllib_external_request_fails_because_of_guard_not_network(egress_guard):
    """실패 원인이 가드임을 확인 — 네트워크가 원래 없어서 실패한 것과 구분."""
    with egress_guard.probe(), pytest.raises(urllib.error.URLError) as exc:
        urllib.request.urlopen(f"http://{TEST_NET}/", timeout=1)
    assert isinstance(exc.value.reason, EgressBlocked)
    assert egress_guard.events and egress_guard.events[-1].host == TEST_NET


def test_loopback_connection_is_allowed_as_control(egress_guard):
    """대조군: 가드가 '모든 소켓 실패'로 통과하는 가짜 차단이 아님."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        client = socket.create_connection(server.getsockname(), timeout=2)
        conn, _ = server.accept()
        client.sendall(b"ping")
        assert conn.recv(4) == b"ping"
        conn.close()
        client.close()
    finally:
        server.close()
    assert egress_guard.events == []


def test_unexpected_egress_outside_probe_is_flagged_as_real_event():
    """probe() 밖의 시도는 '예상치 못한 실제 egress'로 분류된다(conftest가 이걸로 테스트를 실패시킴).
    전역 가드를 오염시키지 않도록 별도 인스턴스로 판정 로직만 검증한다."""
    g = EgressGuard()
    with g.probe(), pytest.raises(EgressBlocked):
        g.check("connect", TEST_NET, 80)
    assert g.unexpected() == []
    with pytest.raises(EgressBlocked):
        g.check("connect", TEST_NET, 80)
    assert [(e.host, e.probe) for e in g.unexpected()] == [(TEST_NET, False)]


def test_unknown_address_shape_is_treated_as_external():
    g = EgressGuard()
    with pytest.raises(EgressBlocked):
        g._check_address("connect", 12345)
