from __future__ import annotations

import copy

import pytest

from tools.egress_guard import GUARD
from tools.guardrails import REGISTRY_PATH, SPEC_PATH
from tools.guardrails.registry import load_registry
from tools.guardrails.spec import Spec, load_spec


@pytest.fixture(scope="session", autouse=True)
def _egress_guard_session():
    """`egress_runtime_block`: 테스트 세션 전체에서 외부 egress를 가드로 차단(테스트환경 한정)."""
    GUARD.install()
    yield GUARD
    GUARD.uninstall()


@pytest.fixture(autouse=True)
def _no_unexpected_egress():
    """probe() 밖에서 일어난 외부 egress 시도 = 예상치 못한 실제 egress → 그 테스트를 실패시킨다."""
    GUARD.reset()
    yield
    unexpected = GUARD.unexpected()
    GUARD.reset()
    if unexpected:
        pytest.fail(f"예상치 못한 외부 egress 시도(가드가 차단): {unexpected}", pytrace=False)


@pytest.fixture
def egress_guard():
    return GUARD


@pytest.fixture(scope="session")
def spec() -> Spec:
    return load_spec(SPEC_PATH)


@pytest.fixture(scope="session")
def _registry_entries() -> list[dict]:
    return load_registry(REGISTRY_PATH)


@pytest.fixture
def entries(_registry_entries) -> list[dict]:
    """실제 guardrails.yaml의 깊은 복사본 — 적대적 테스트가 마음껏 위조한다."""
    return copy.deepcopy(_registry_entries)
