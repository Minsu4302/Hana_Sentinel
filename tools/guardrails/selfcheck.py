"""manifest 자기검증(동적) — (A) §3.1 `manifest_selfcheck`. pytest 플러그인.

`guardrails check`의 정적 확인(검증 테스트 파일·함수 실재, registry.resolve_test)을 넘어, 게이트 실행에서
enforced 키가 가리키는 검증 테스트 노드가 **실제로 수집되고 통과했는지**를 확인한다. 하나라도
미수집(수집 제외·선택 해제·collection error)·skip·xfail·실패·미실행이면 세션을 실패시킨다(fail-closed).

  python -m pytest -p tools.guardrails.selfcheck --manifest-selfcheck=guardrails.yaml   (make test)

과대평가 금지(경계): 이 검사는 '등록·수집·통과'만 확인한다. 그 테스트가 해당 가드레일을 *실질적으로*
검증하는지는 테스트 내용의 책임이며 여기서 떠안지 않는다. 참칭(not_implemented 등의 enforced 주장) 차단은
registry.validate(`guardrails check`)의 몫이고, 이 플러그인은 enforced로 *선언된* 키만 본다.

활성 표지: 활성일 때 항상 `manifest selfcheck: 활성 module=<이 파일> ...` 한 줄을 출력한다. 검사가 실제로
돌았는지(플러그인 미로드·다른 사본 로드가 아닌지)를 바깥에서 확인하는 근거다(W1-08 '변이 거짓 통과' 교훈).
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.guardrails.registry import RegistryError, load_registry

OPTION = "--manifest-selfcheck"
STAMP = "manifest selfcheck: 활성"
PASSED = "passed"


def enforced_nodes(entries: list) -> dict[str, list[str]]:
    """enforced로 선언된 키 → 검증 테스트 노드 ID. 형식 검증은 registry.validate 몫이라 여기선 읽기만 한다."""
    out: dict[str, list[str]] = {}
    for e in entries:
        status = e.get("week1_status") if isinstance(e, dict) else None
        if isinstance(status, dict) and status.get("state") == "enforced":
            out[e.get("id")] = list(e.get("verification_tests") or [])
    return out


def _instances(node: str, collected: list[str]) -> list[str]:
    """레지스트리 노드에 대응하는 수집 노드. 매개변수화 함수는 대괄호 없이 적으면 모든 인스턴스가 대응."""
    if "[" in node:
        return [c for c in collected if c == node]
    return [c for c in collected if c == node or c.startswith(node + "[")]


def evaluate(enforced: dict[str, list[str]], collected: list[str], outcomes: dict[str, str]) -> list[str]:
    """순수 판정. collected = 실제 실행 대상으로 수집된 노드, outcomes = 노드별 최종 결과."""
    problems: list[str] = []
    if not any(enforced.values()):
        problems.append("enforced 검증 노드 0개 — 빈 검사는 통과가 아님")
    for key, nodes in enforced.items():
        if not nodes:
            problems.append(f"{key}: enforced인데 검증 테스트 식별자 없음")
        for node in nodes:
            inst = _instances(node, collected)
            if not inst:
                problems.append(f"{key}: {node} 미수집 — 수집 제외·선택 해제·collection error·부재")
                continue
            for c in inst:
                outcome = outcomes.get(c, "미실행")
                if outcome != PASSED:
                    problems.append(f"{key}: {c} 미통과({outcome})")
    return problems


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(OPTION, dest="manifest_selfcheck", default=None, metavar="GUARDRAILS_YAML",
                     help="enforced 키의 검증 테스트가 실제 수집·통과했는지 확인(실패 시 세션 실패)")


def pytest_configure(config: pytest.Config) -> None:
    path = config.getoption("manifest_selfcheck")
    if path:
        config.pluginmanager.register(_SelfCheck(Path(path)), "manifest-selfcheck")


class _SelfCheck:
    def __init__(self, registry_path: Path):
        self.registry_path = registry_path
        self.collected: list[str] = []
        self.outcomes: dict[str, str] = {}
        self.enforced: dict[str, list[str]] = {}
        self.problems: list[str] = []

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        # trylast: -k/-m 선택 해제 등 다른 수정이 끝난 뒤의 '실제 실행 대상'을 기록한다
        self.collected = [i.nodeid for i in items]

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if hasattr(report, "wasxfail"):
            self.outcomes[report.nodeid] = "xfail"  # xfail·xpass는 강제 증거가 아님
        elif report.when == "call":
            self.outcomes[report.nodeid] = report.outcome
        elif report.failed or (report.when == "setup" and report.skipped):
            # setup 실패·skip(→ call 없음), teardown 실패(→ call 결과를 덮어씀)
            self.outcomes[report.nodeid] = f"{report.when} {report.outcome}"

    @pytest.hookimpl(tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        try:
            self.enforced = enforced_nodes(load_registry(self.registry_path))
        except (OSError, RegistryError, yaml.YAMLError) as exc:
            self.problems = [f"레지스트리 읽기 실패 — 통과로 취급하지 않음: {exc}"]
        else:
            self.problems = evaluate(self.enforced, self.collected, self.outcomes)
        if self.problems and session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter) -> None:
        nodes = sum(len(v) for v in self.enforced.values())
        terminalreporter.write_line(f"{STAMP} module={Path(__file__).resolve()} "
                                    f"keys={len(self.enforced)} nodes={nodes}")
        if self.problems:
            terminalreporter.write_line(f"manifest selfcheck: 실패 ({len(self.problems)}건)", red=True)
            for p in self.problems:
                terminalreporter.write_line(f"  - {p}", red=True)
        else:
            terminalreporter.write_line("manifest selfcheck: 통과 — enforced 검증 노드 전부 수집·통과", green=True)
