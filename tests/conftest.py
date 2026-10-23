from __future__ import annotations

import copy

import pytest

from tools.guardrails import REGISTRY_PATH, SPEC_PATH
from tools.guardrails.registry import load_registry
from tools.guardrails.spec import Spec, load_spec


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
