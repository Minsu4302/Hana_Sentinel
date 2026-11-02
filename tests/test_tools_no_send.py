"""`tools_no_external_send` — tools/ 전체에 송신·소켓 import와 동적 import 0. (A) §1.3 ⓑ 해석(목적지 기준), §3.1.

'위조 거부'로 증명한다: 실제 tools/ 트리를 복사한 뒤 새 하위 패키지·깊은 중첩 패키지에 심은 송신 import와 동적 import를
검사가 잡는다(검사 대상이 고정 목록이 아니라 재귀 열거임을 실제 구조로 보인다). 허용 import는 통과(대조), 빈 대상·없는
경로는 오류(통과 아님). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
한계: tools/ 소스의 직접 import만 — 개발 의존성 내부·하위 프로세스는 범위 밖(manifest note).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.arch_boundary import DYNAMIC, SEND, TESTS, BoundaryScanError, tools_send_violations
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPO_ROOT / "tools"


def _tools_copy(tmp_path: Path) -> Path:
    target = tmp_path / "tools"
    shutil.copytree(TOOLS_ROOT, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def _plant(root: Path, rel: str, src: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in path.relative_to(root).parents:
        if str(parent) != ".":
            (root / parent / "__init__.py").touch()
    path.write_text(src + "\n", encoding="utf-8")


def test_real_tools_tree_has_no_send_or_dynamic_import():
    assert [v.render() for v in tools_send_violations(TOOLS_ROOT)] == []


@pytest.mark.parametrize("src", ["import socket", "from urllib.request import urlopen", "import requests",
                                 "import httpx", "from http.client import HTTPSConnection", "import asyncio\nasyncio.open_connection"])
def test_send_import_in_a_brand_new_subpackage_is_caught(tmp_path, src):
    root = _tools_copy(tmp_path)
    _plant(root, "llm_adapter_sibling/client.py", src)  # 기존 어디에도 없는 새 하위 패키지(tools/eval의 형제)
    found = tools_send_violations(root)
    assert {v.kind for v in found} == {SEND} and all(v.path.endswith("client.py") for v in found)


def test_send_import_in_a_deeply_nested_subpackage_is_caught(tmp_path):
    root = _tools_copy(tmp_path)
    _plant(root, "eval/backends/remote/deep/sender.py", "import json\nfrom urllib import request\n")
    found = tools_send_violations(root)
    assert [(Path(v.path).name, v.line, v.kind) for v in found] == [("sender.py", 2, SEND)]


@pytest.mark.parametrize("src", ["import importlib\nname = 'sock' + 'et'\nimportlib.import_module(name)",
                                 "__import__(name)", "exec('import socket')"])
def test_dynamic_import_in_tools_is_caught(tmp_path, src):
    root = _tools_copy(tmp_path)
    _plant(root, "dataset/planted.py", src)
    assert DYNAMIC in {v.kind for v in tools_send_violations(root)}


@pytest.mark.parametrize("src", ["from tests.support.egress_guard import EgressGuard", "import tests.support",
                                 "import tests.support.egress_guard as g", "from tests import conftest",
                                 "import tests\nx = tests.support.egress_guard.GUARD",
                                 "import importlib\nimportlib.import_module('tests.support.egress_guard')"])
def test_tests_package_import_in_tools_is_caught(tmp_path, src):
    """테스트 가드(소켓을 다룸)는 tests/support로 옮겼다 — tools/가 그것을 import해 송신 검사를 세탁하지 못한다."""
    root = _tools_copy(tmp_path)
    _plant(root, "llm_adapter_sibling/laundering.py", src)
    assert TESTS in {v.kind for v in tools_send_violations(root)}


def test_allowed_imports_in_a_new_subpackage_pass_as_control(tmp_path):
    root = _tools_copy(tmp_path)
    _plant(root, "new_report/render.py",
           "import json\nfrom http import HTTPStatus\nfrom urllib.parse import urlsplit\nfrom sentinel import strict_json\n"
           "import tests_helpers_not_the_tests_package\n")  # 이름이 tests로 시작할 뿐인 다른 패키지는 대상 아님
    assert tools_send_violations(root) == []


def test_egress_guard_lives_in_tests_not_tools():
    assert not (TOOLS_ROOT / "egress_guard.py").exists()
    assert (REPO_ROOT / "tests" / "support" / "egress_guard.py").exists()


def test_empty_or_missing_target_is_an_error_not_a_pass(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(BoundaryScanError):
        tools_send_violations(tmp_path / "empty")
    with pytest.raises(BoundaryScanError):
        tools_send_violations(tmp_path / "does_not_exist")


STAMP = "tools_no_send_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_tools_no_send.py::"
_LINE = "    return [v for v in scan_package(tools_root) if v.kind in TOOLS_SEND_KINDS]\n"
MUTATIONS = {
    "check_off": (_LINE, "    return []\n",
                  [_T + "test_send_import_in_a_brand_new_subpackage_is_caught",
                   _T + "test_send_import_in_a_deeply_nested_subpackage_is_caught",
                   _T + "test_dynamic_import_in_tools_is_caught"]),
    "fixed_directory_list": (_LINE, "    return [v for d in ('fixture_masker', 'dataset') for v in scan_package(tools_root / d)\n"
                                    "            if v.kind in TOOLS_SEND_KINDS]\n",
                             [_T + "test_send_import_in_a_brand_new_subpackage_is_caught",
                              _T + "test_send_import_in_a_deeply_nested_subpackage_is_caught"]),
    "dynamic_not_forbidden": ("TOOLS_SEND_KINDS = (SEND, DYNAMIC, TESTS)\n", "TOOLS_SEND_KINDS = (SEND, TESTS)\n",
                              [_T + "test_dynamic_import_in_tools_is_caught"]),
    "tests_not_forbidden": ("TOOLS_SEND_KINDS = (SEND, DYNAMIC, TESTS)\n", "TOOLS_SEND_KINDS = (SEND, DYNAMIC)\n",
                            [_T + "test_tests_package_import_in_tools_is_caught"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_tools_send_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", "tools/arch_boundary.py", old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), "tools.arch_boundary", *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
