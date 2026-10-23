"""`manifest_selfcheck` — enforced 검증 노드의 '실제 수집·통과' 동적 확인 (W1-09).

정적 확인(registry.resolve_test: 파일·함수 실재)만으로는 "파일은 있지만 수집·통과 안 됨"을 못 잡는다.
샌드박스 프로젝트에 실제 pytest를 돌려, 정적으로는 실재하지만 미수집/skip/xfail/실패/선택 해제/collection
error인 노드를 enforced로 선언하면 selfcheck가 세션을 실패시킴을 보인다(위조 거부).

거짓 통과 방지(W1-08 교훈): '종료코드 ≠ 0'만으로 거부를 인정하지 않는다 — 플러그인 미로드·옵션 오류도
≠ 0이다. 거부 판정은 (1) 활성 표지가 기대한 모듈을 가리키고 (2) 기대한 거부 사유가 출력될 때만 인정한다.
변이 확인은 tools.mutation_guard로 '치환 성공 + 실행 중 로드된 모듈 = 변이본'을 먼저 증명한다.

과대평가 금지: 여기서 증명하는 것은 '등록·수집·통과' 확인뿐이다. 각 검증 테스트가 그 가드레일을
실질적으로 검증하는지는 그 테스트 내용의 책임이다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.guardrails import REGISTRY_PATH, REPO_ROOT
from tools.guardrails.registry import resolve_test
from tools.guardrails.selfcheck import STAMP, enforced_nodes, evaluate
from tools.mutation_guard import MutationNotApplied, apply_mutation, assert_loaded_from, copy_with_mutation

SELFCHECK_FILE = (REPO_ROOT / "tools" / "guardrails" / "selfcheck.py").resolve()

OK_TEST = "def test_ok():\n    assert True\n"


# ── 순수 판정 ────────────────────────────────────────────────────

ENF = {"k1": ["t.py::test_a"], "k2": ["t.py::test_b"]}


def test_evaluate_accepts_when_every_enforced_node_collected_and_passed():
    assert evaluate(ENF, ["t.py::test_a", "t.py::test_b", "t.py::other"],
                    {"t.py::test_a": "passed", "t.py::test_b": "passed"}) == []


@pytest.mark.parametrize("outcome", ["skipped", "failed", "xfail", "setup failed", "setup skipped", "teardown failed"])
def test_evaluate_rejects_non_passing_outcome(outcome):
    probs = evaluate(ENF, ["t.py::test_a", "t.py::test_b"], {"t.py::test_a": "passed", "t.py::test_b": outcome})
    assert probs == [f"k2: t.py::test_b 미통과({outcome})"]


def test_evaluate_rejects_uncollected_node():
    probs = evaluate(ENF, ["t.py::test_a"], {"t.py::test_a": "passed"})
    assert len(probs) == 1 and probs[0].startswith("k2: t.py::test_b 미수집")


def test_evaluate_rejects_collected_but_never_run():
    assert evaluate(ENF, ["t.py::test_a", "t.py::test_b"], {"t.py::test_a": "passed"}) == [
        "k2: t.py::test_b 미통과(미실행)"]


def test_evaluate_requires_every_parametrized_instance_to_pass():
    enf = {"k": ["t.py::test_p"]}
    collected = ["t.py::test_p[a]", "t.py::test_p[b]"]
    assert evaluate(enf, collected, {"t.py::test_p[a]": "passed", "t.py::test_p[b]": "passed"}) == []
    assert evaluate(enf, collected, {"t.py::test_p[a]": "passed", "t.py::test_p[b]": "skipped"}) == [
        "k: t.py::test_p[b] 미통과(skipped)"]
    # 접두어가 같은 다른 함수(test_p2)는 인스턴스로 치지 않는다
    assert evaluate(enf, ["t.py::test_p2"], {"t.py::test_p2": "passed"})[0].startswith("k: t.py::test_p 미수집")


def test_evaluate_rejects_empty_check_and_enforced_without_nodes():
    assert evaluate({}, [], {}) == ["enforced 검증 노드 0개 — 빈 검사는 통과가 아님"]
    assert "k2: enforced인데 검증 테스트 식별자 없음" in evaluate({**ENF, "k2": []}, ["t.py::test_a"],
                                                              {"t.py::test_a": "passed"})


def test_enforced_nodes_reads_only_enforced_declarations():
    entries = [
        {"id": "a", "week1_status": {"state": "enforced"}, "verification_tests": ["t.py::test_a"]},
        {"id": "b", "week1_status": {"state": "not_implemented", "target": "2주차"}, "verification_tests": []},
        {"id": "c", "week1_status": {"state": "derived"}, "verification_tests": []},
    ]
    assert enforced_nodes(entries) == {"a": ["t.py::test_a"]}


# ── 샌드박스: 실제 pytest 실행 ─────────────────────────────────────

def _registry(enforced: dict[str, list[str]]) -> str:
    entries = [{"id": k, "week1_status": {"state": "enforced"}, "verification_tests": v} for k, v in enforced.items()]
    return json.dumps({"schema_version": "1", "guardrails": entries}, ensure_ascii=False)  # JSON ⊂ YAML


def _run(tmp: Path, files: dict[str, str], enforced: dict[str, list[str]] | str | None, *args: str,
         pythonpath: Path = REPO_ROOT, plugin: str = "tools.guardrails.selfcheck") -> subprocess.CompletedProcess:
    """enforced: None이면 selfcheck 없이 실행, 문자열이면 레지스트리 원문 그대로."""
    proj = tmp / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n", encoding="utf-8")
    for name, body in files.items():
        (proj / name).write_text(body, encoding="utf-8")
    cmd = [sys.executable, "-m", "pytest", "-c", str(proj / "pytest.ini"), "--rootdir", str(proj)]
    if enforced is not None:
        registry = enforced if isinstance(enforced, str) else _registry(enforced)
        (proj / "guardrails.yaml").write_text(registry, encoding="utf-8")
        cmd += ["-p", plugin, "--manifest-selfcheck=guardrails.yaml"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    env.update(PYTHONPATH=str(pythonpath), PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(cmd + list(args), cwd=proj, env=env, capture_output=True, text=True, encoding="utf-8",
                          timeout=120)


def _expect_accepted(r: subprocess.CompletedProcess, module: Path = SELFCHECK_FILE) -> None:
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, module)  # 검사가 실제로, 기대한 모듈로 돌았는가
    assert r.returncode == 0, out
    assert "manifest selfcheck: 통과" in out


def _expect_rejected(r: subprocess.CompletedProcess, *reasons: str, module: Path = SELFCHECK_FILE) -> None:
    """'≠ 0'은 거부 증거가 아니다 — 활성 표지 + 거부 사유가 있어야 selfcheck의 거부로 인정."""
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, module)
    assert r.returncode != 0, out
    assert "manifest selfcheck: 실패" in out, out
    for reason in reasons:
        assert reason in out, out


def test_clean_sandbox_passes_with_active_stamp(tmp_path):
    files = {"test_a.py": OK_TEST, "test_b.py": "import pytest\n\n@pytest.mark.parametrize('x', [1, 2])\n"
                                                "def test_p(x):\n    assert x\n"}
    r = _run(tmp_path, files, {"k1": ["test_a.py::test_ok"], "k2": ["test_b.py::test_p"]})
    _expect_accepted(r)
    assert "keys=2 nodes=2" in r.stdout


# "파일은 있지만 수집 안 됨" — 정적 확인(resolve_test)은 통과하고 pytest 자체도 종료코드 0인데 selfcheck만 잡는다
UNCOLLECTED = {
    "class_with_init": ("class TestX:\n    def __init__(self):\n        pass\n\n    def test_ok(self):\n"
                        "        assert True\n", "test_x.py::TestX::test_ok", {}),
    "module_dunder_test_false": ("__test__ = False\n\n" + OK_TEST, "test_x.py::test_ok", {}),
    "conftest_collect_ignore": (OK_TEST, "test_x.py::test_ok", {"conftest.py": "collect_ignore = ['test_x.py']\n"}),
}


@pytest.mark.parametrize("variant", sorted(UNCOLLECTED))
def test_rejects_statically_present_but_uncollected_node(tmp_path, variant):
    body, node, extra = UNCOLLECTED[variant]
    files = {"test_x.py": body, "test_other.py": OK_TEST, **extra}
    # 정적 확인은 이 노드를 '실재'로 본다 — W1-00 수준의 확인으로는 못 잡는 구멍
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "test_x.py").write_text(body, encoding="utf-8")
    assert resolve_test(tmp_path / "proj", node)
    assert _run(tmp_path, files, None).returncode == 0  # selfcheck 없이 pytest는 '성공'
    _expect_rejected(_run(tmp_path, files, {"k": [node]}), f"k: {node} 미수집")


SKIPPED = {
    "mark_skip": "import pytest\n\n@pytest.mark.skip(reason='later')\ndef test_t():\n    assert True\n",
    "skipif": "import pytest\n\n@pytest.mark.skipif(True, reason='env')\ndef test_t():\n    assert True\n",
    "skip_in_call": "import pytest\n\ndef test_t():\n    pytest.skip('runtime')\n",
    "importorskip_fixture": "import pytest\n\n@pytest.fixture\ndef dep():\n"
                            "    pytest.importorskip('no_such_module_w1_09')\n\ndef test_t(dep):\n    assert True\n",
    "xfail": "import pytest\n\n@pytest.mark.xfail(reason='known')\ndef test_t():\n    assert False\n",
    "xpass": "import pytest\n\n@pytest.mark.xfail(reason='flaky', strict=False)\ndef test_t():\n    assert True\n",
}


@pytest.mark.parametrize("variant", sorted(SKIPPED))
def test_rejects_enforced_node_that_is_skipped_or_xfail(tmp_path, variant):
    files = {"test_x.py": SKIPPED[variant]}
    assert _run(tmp_path, files, None).returncode == 0  # selfcheck 없이 pytest는 '성공'
    _expect_rejected(_run(tmp_path, files, {"k": ["test_x.py::test_t"]}), "k: test_x.py::test_t 미통과(")


@pytest.mark.parametrize("body,reason", [
    ("def test_t():\n    assert False\n", "미통과(failed)"),
    ("import pytest\n\n@pytest.fixture\ndef f():\n    raise RuntimeError\n\ndef test_t(f):\n    pass\n",
     "미통과(setup failed)"),
    ("import pytest\n\n@pytest.fixture\ndef f():\n    yield\n    raise RuntimeError\n\ndef test_t(f):\n    pass\n",
     "미통과(teardown failed)"),
], ids=["call", "setup", "teardown"])
def test_rejects_enforced_node_that_fails(tmp_path, body, reason):
    _expect_rejected(_run(tmp_path, {"test_x.py": body}, {"k": ["test_x.py::test_t"]}), f"test_x.py::test_t {reason}")


def test_rejects_enforced_node_that_does_not_exist(tmp_path):
    _expect_rejected(_run(tmp_path, {"test_x.py": OK_TEST}, {"k": ["test_x.py::test_missing"]}),
                     "k: test_x.py::test_missing 미수집")


def test_rejects_enforced_node_deselected_from_the_run(tmp_path):
    files = {"test_x.py": OK_TEST + "\n\ndef test_other():\n    assert True\n"}
    assert _run(tmp_path, files, None, "-k", "other").returncode == 0
    _expect_rejected(_run(tmp_path, files, {"k": ["test_x.py::test_ok"]}, "-k", "other"),
                     "k: test_x.py::test_ok 미수집")


def test_rejects_enforced_node_in_file_with_collection_error(tmp_path):
    files = {"test_x.py": "import no_such_module_w1_09\n\n" + OK_TEST, "test_other.py": OK_TEST}
    _expect_rejected(_run(tmp_path, files, {"k": ["test_x.py::test_ok"]}, "--continue-on-collection-errors"),
                     "k: test_x.py::test_ok 미수집")


@pytest.mark.parametrize("registry", ["schema_version: '0'\nguardrails: []\n", "{{{ not yaml"],
                         ids=["wrong_schema", "unparseable"])
def test_rejects_unreadable_registry(tmp_path, registry):
    _expect_rejected(_run(tmp_path, {"test_x.py": OK_TEST}, registry), "레지스트리 읽기 실패")


# ── 게이트 배선 ─────────────────────────────────────────────────

def test_make_test_runs_selfcheck_against_the_real_registry():
    """`make verify`의 pytest 단계가 실제 레지스트리로 selfcheck를 켠다(빠지면 동적 확인이 조용히 사라짐)."""
    recipe = [line.strip() for line in (REPO_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()]
    i = recipe.index("test:")
    assert recipe[i + 1] == "$(PYTHON) -m pytest -p tools.guardrails.selfcheck --manifest-selfcheck=guardrails.yaml"
    assert REGISTRY_PATH == REPO_ROOT / "guardrails.yaml"


# ── 변이 적용 유효성 (W1-08 교훈) ───────────────────────────────────

def test_nonzero_exit_without_active_stamp_is_not_rejection_evidence(tmp_path):
    """거짓 통과 재현: 플러그인을 못 불러도 종료코드는 ≠ 0이다. 순진한 '≠ 0 = 거부' 판정은 이걸 통과시킨다."""
    r = _run(tmp_path, {"test_x.py": OK_TEST}, {"k": ["test_x.py::test_missing"]},
             plugin="tools.guardrails.no_such_plugin")
    assert r.returncode != 0  # 순진한 판정이라면 여기서 '거부 확인'으로 끝났을 것
    with pytest.raises(MutationNotApplied, match="활성 표지"):
        _expect_rejected(r, "미수집")


@pytest.mark.parametrize("source,old", [("a = 1\n", "b = 2"), ("x\nx\n", "x")], ids=["absent", "ambiguous"])
def test_mutation_whose_target_is_absent_or_ambiguous_is_refused(source, old):
    with pytest.raises(MutationNotApplied, match="정확히 1회"):
        apply_mutation(source, old, "pass")


def test_mutation_that_changes_nothing_is_refused():
    with pytest.raises(MutationNotApplied, match="원문과 같음"):
        apply_mutation("a = 1\n", "a = 1", "a = 1")


# (이름, 원문, 변이, 위조 파일, 위조 노드) — 변이가 그 검사를 끄면 같은 위조가 통과해야 한다
MUTATIONS = {
    "collect_check_off": ("            if not inst:\n", "            if False:\n",
                          UNCOLLECTED["class_with_init"][0], "test_x.py::TestX::test_ok"),
    "pass_check_off": ("                if outcome != PASSED:\n", "                if False:\n",
                       SKIPPED["mark_skip"], "test_x.py::test_t"),
    "xfail_record_off": ('        if hasattr(report, "wasxfail"):\n', "        if False:\n",
                         SKIPPED["xpass"], "test_x.py::test_t"),
    "exitstatus_off": ("            session.exitstatus = pytest.ExitCode.TESTS_FAILED\n", "            pass\n",
                       SKIPPED["mark_skip"], "test_x.py::test_t"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    """원본은 위조를 거부하고, 그 검사를 끈 변이본은 통과시킨다 — 단, 변이본이 실제로 로드됐음을 먼저 증명."""
    old, new, body, node = MUTATIONS[name]
    files = {"test_x.py": body, "test_other.py": OK_TEST}
    _expect_rejected(_run(tmp_path / "orig", files, {"k": [node]}))

    mut_root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools/__init__.py", "tools/guardrails"], mut_root,
                                "tools/guardrails/selfcheck.py", old, new)
    r = _run(tmp_path / "run", files, {"k": [node]}, pythonpath=mut_root)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 0, f"변이 {name}가 살아남지 못함 — 이 검사가 하중을 지지 않거나 다른 경로가 잡음\n{out}"


def test_mutant_shadowed_by_original_module_is_detected(tmp_path):
    """W1-08 함정 재현: 변이본을 만들었지만 실행은 원본 모듈을 불렀다 → 장치가 '변이 미적용'으로 잡는다."""
    old, new, body, node = MUTATIONS["pass_check_off"]
    mutant = copy_with_mutation(REPO_ROOT, ["tools/__init__.py", "tools/guardrails"], tmp_path / "mut",
                                "tools/guardrails/selfcheck.py", old, new)
    r = _run(tmp_path / "run", {"test_x.py": body}, {"k": [node]}, pythonpath=REPO_ROOT)  # 경로 실수
    with pytest.raises(MutationNotApplied, match="다른 사본"):
        assert_loaded_from(r.stdout + r.stderr, STAMP, mutant)
