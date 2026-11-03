"""manifest 정직성·파생 사슬 — 합성 레지스트리로 하는 위조 거부. (A) §3 → guardrails.yaml → manifest.
(이 파일이 증명하는 키 이름은 guardrails.yaml의 검증 노드 쪽에 있다 — 이 파일에는 실제 키 이름을 쓰지 않는다.)

실제 레지스트리의 상태(어떤 키가 지금 enforced인가)는 정상 진척으로 바뀐다 — 그 상태를 '예시'로 쓰는 테스트는 위조가 아니라
진척을 실패로 만든다(v1.20 미해결 ①: 하네스·v1.20 PR에서 두 번 재발). 그래서 상태 예시는 전부 이 파일의 합성 (A) §3 텍스트와
합성 레지스트리로 한다. 실제 레지스트리의 키 이름은 이 파일에 한 글자도 없다(`test_this_file_names_no_real_guardrail_key`가
고정). 실제 레지스트리 자체의 정합(재파생 일치·실제 파생 롤업)은 `test_guardrails.py`가 본다.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import tools.guardrails.__main__ as cli
from tools.guardrails import REGISTRY_PATH, REPO_ROOT
from tools.guardrails.manifest import derive_manifest, render_manifest
from tools.guardrails.registry import RegistryError, load_registry, render_yaml, sync, validate
from tools.guardrails.spec import TABLE_HEADER, SpecError, parse_spec
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

# 위조에 쓸 '실재하는' 검증 테스트(이 파일 안의 함수) — 테스트가 실재해도 (A)를 넘는 주장은 거부돼야 한다.
REAL_TEST = "tests/test_guardrails_synthetic.py::test_synthetic_registry_is_valid_as_control"
HEADER = "| 규칙 | 목표층위 | 상태 | manifest 키 |\n|---|---|---|---|\n"

SYN_SPEC = f"""# (A) 합성 — 테스트 전용
## 3. 가드레일 — 강제 매핑표 v9.9 (FROZEN)
### 3.1 합성 실행
{HEADER}| 합성 증명됨 | 테스트 | enforced | `syn_proven` |
| 합성 미구현 | 테스트 | not_implemented → 합성 시점 | `syn_pending` |
| 합성 검증불가 | 테스트 | unverifiable | `syn_unverifiable` |
### 3.2 합성 입력
{HEADER}| 합성 자식 a | 테스트 | enforced | `syn_child_a` |
| 합성 자식 b | 테스트 | enforced | `syn_child_b` |
### 3.3 합성 민감
{HEADER}| 합성 다른 미구현 | 아키텍처 테스트 | not_implemented → 다른 합성 시점 | `syn_pending_two` |
### 3.4 합성 공통
{HEADER}| 합성 층위 | 테스트 | enforced | `syn_layered` |
### 3.5 합성 출력
{HEADER}| 합성 롤업 | 파생(하위 4키 AND) | derived † | `syn_rollup` |

> **† `syn_rollup` (파생 롤업):** `syn_child_a ∧ syn_child_b`.

## 4. 합성 끝
"""
PROMOTED = ("syn_proven", "syn_child_a", "syn_child_b", "syn_layered")


@pytest.fixture
def syn_spec():
    return parse_spec(SYN_SPEC)


@pytest.fixture
def syn_entries(syn_spec):
    entries = sync(syn_spec, [])
    for e in entries:
        if e["id"] in PROMOTED:
            e["status"] = {"state": "enforced"}
            e["verification_tests"] = [REAL_TEST]
    return entries


def _get(entries, key):
    return next(e for e in entries if e["id"] == key)


def _rejected(entries, spec, *needles):
    with pytest.raises(RegistryError) as exc:
        validate(entries, spec, REPO_ROOT)
    for n in needles:
        assert n in str(exc.value)


# ── 대조 ─────────────────────────────────────────────────────────

def test_synthetic_registry_is_valid_as_control(syn_spec, syn_entries):
    validate(syn_entries, syn_spec, REPO_ROOT)
    caps = derive_manifest(syn_entries, syn_spec, REPO_ROOT)["capabilities"]
    assert caps["syn_rollup"]["effective_status"] == "enforced" and caps["syn_pending"]["status"] == "not_implemented"


def test_this_file_names_no_real_guardrail_key():
    """합성 예시가 실제 레지스트리에 의존하지 않음 — 실제 키 이름 문자열 0."""
    text = Path(__file__).read_text(encoding="utf-8")
    real = {e["id"] for e in load_registry(REGISTRY_PATH)}
    assert real and not {k for k in real if re.search(rf"\b{re.escape(k)}\b", text)}


# ── 위조 거부: 거짓 enforced / 참칭 ─────────────────────────────────

def test_rejects_enforced_without_verification_tests(syn_spec, syn_entries):
    _get(syn_entries, "syn_proven")["verification_tests"] = []
    _rejected(syn_entries, syn_spec, "syn_proven", "검증 테스트 식별자 없음")


def test_rejects_enforced_pointing_to_nonexistent_test(syn_spec, syn_entries):
    _get(syn_entries, "syn_proven")["verification_tests"] = ["tests/test_guardrails_synthetic.py::test_does_not_exist"]
    _rejected(syn_entries, syn_spec, "syn_proven", "실재하지 않음")


def test_rejects_enforced_pointing_to_non_test_function(syn_spec, syn_entries):
    _get(syn_entries, "syn_proven")["verification_tests"] = ["tests/test_guardrails_synthetic.py::_get"]
    _rejected(syn_entries, syn_spec, "syn_proven", "실재하지 않음")


@pytest.mark.parametrize("key", ["syn_pending", "syn_pending_two"])
def test_rejects_not_implemented_key_claimed_as_enforced(syn_spec, syn_entries, key):
    """테스트가 실재해도 (A)가 not_implemented로 둔 키는 enforced가 될 수 없다."""
    e = _get(syn_entries, key)
    e["status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(syn_entries, syn_spec, key, "참칭")


def test_rejects_unverifiable_key_claimed_as_enforced(syn_spec, syn_entries):
    e = _get(syn_entries, "syn_unverifiable")
    e["status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(syn_entries, syn_spec, "syn_unverifiable", "참칭")


def test_rejects_derived_rollup_claimed_as_enforced(syn_spec, syn_entries):
    e = _get(syn_entries, "syn_rollup")
    e["status"] = {"state": "enforced"}
    e["verification_tests"] = [REAL_TEST]
    _rejected(syn_entries, syn_spec, "syn_rollup", "참칭")


def test_rejects_target_drift(syn_spec, syn_entries):
    """목표를 바꿔 적는 것도 (A)와 다르면 거부."""
    _get(syn_entries, "syn_pending")["status"]["target"] = "앞당긴 시점"
    _rejected(syn_entries, syn_spec, "syn_pending", "(A) 파생값")


def test_rejects_unknown_status(syn_spec, syn_entries):
    _get(syn_entries, "syn_pending")["status"] = {"state": "mostly_enforced"}
    _rejected(syn_entries, syn_spec, "미지 status", "mostly_enforced")


def test_rejects_tests_attached_to_non_enforced_key(syn_spec, syn_entries):
    _get(syn_entries, "syn_pending")["verification_tests"] = [REAL_TEST]
    _rejected(syn_entries, syn_spec, "syn_pending", "enforced만 허용")


def test_rejects_key_not_in_design_decision(syn_spec, syn_entries):
    extra = copy.deepcopy(_get(syn_entries, "syn_pending"))
    extra["id"] = extra["manifest_key"] = "invented_guardrail"
    syn_entries.append(extra)
    _rejected(syn_entries, syn_spec, "invented_guardrail", "(A) §3에 없는 키")


def test_rejects_derived_rollup_with_unknown_child(syn_spec, syn_entries):
    _get(syn_entries, "syn_rollup")["status"]["derived_from"].append("ghost_key")
    _rejected(syn_entries, syn_spec, "ghost_key")


# ── 위조 거부: (A) 정본 파서는 추측하지 않는다 ───────────────────────

def test_spec_parser_requires_target_for_not_implemented():
    bad = SYN_SPEC.replace("| not_implemented → 합성 시점 | `syn_pending` |", "| not_implemented | `syn_pending` |")
    with pytest.raises(SpecError, match="해석할 수 없는 상태 표기"):
        parse_spec(bad)


def test_spec_parser_rejects_unparseable_status():
    bad = SYN_SPEC.replace("| not_implemented → 합성 시점 | `syn_pending` |", "| 거의 됨 | `syn_pending` |")
    with pytest.raises(SpecError, match="해석할 수 없는 상태 표기"):
        parse_spec(bad)


def test_spec_parser_rejects_unmapped_target_layer():
    bad = SYN_SPEC.replace("| 합성 층위 | 테스트 | enforced |", "| 합성 층위 | 런타임 감시 | enforced |")
    with pytest.raises(SpecError, match="매핑되지 않은 목표층위"):
        parse_spec(bad)


def test_targetless_derived_without_child_list_is_rejected():
    bad = SYN_SPEC.replace("`syn_child_a ∧ syn_child_b`", "`syn_child_a`")
    with pytest.raises(SpecError, match="하위 키 목록"):
        parse_spec(bad)


# ── 위조 거부: 표 머리(옛 머리 = 오류, 호환 경로 없음) ──────────────────────

def test_new_table_header_is_accepted():
    assert TABLE_HEADER == ["규칙", "목표층위", "상태", "manifest 키"]
    assert {r.key for r in parse_spec(SYN_SPEC).rows} >= {"syn_proven", "syn_rollup"}


@pytest.mark.parametrize("bad_header", [
    "| 규칙 | 목표층위 | 1주차 상태 | manifest 키 |",   # 옛 머리
    "| 규칙 | 목표층위 | 현재 상태 | manifest 키 |",   # 열 이름 하나 변형
    "| 목표층위 | 규칙 | 상태 | manifest 키 |",       # 열 순서 바꿈
    "| 규칙 | 목표층위 | 상태 |",                     # 열 하나 빠짐
])
@pytest.mark.parametrize("section", ["3.1", "3.5"])
def test_old_or_altered_table_header_is_a_parse_error(bad_header, section):
    marker = f"### {section} "
    head, tail = SYN_SPEC.split(marker, 1)
    tail = tail.replace("| 규칙 | 목표층위 | 상태 | manifest 키 |", bad_header, 1)
    with pytest.raises(SpecError, match="표 머리"):
        parse_spec(head + marker + tail)


# ── 위조 거부: 생성기·검사기(fail-closed, 합성 사본) ──────────────────────

@pytest.fixture
def sandbox(tmp_path, monkeypatch, syn_spec, syn_entries):
    """CLI가 합성 (A)·레지스트리·manifest 사본을 읽고 쓰게 한다."""
    spec_path, reg, man = tmp_path / "design.md", tmp_path / "guardrails.yaml", tmp_path / "manifest.json"
    spec_path.write_text(SYN_SPEC, encoding="utf-8")
    reg.write_text(render_yaml(syn_entries, syn_spec), encoding="utf-8")
    man.write_text(render_manifest(derive_manifest(syn_entries, syn_spec, REPO_ROOT)), encoding="utf-8")
    for name, path in (("SPEC_PATH", spec_path), ("REGISTRY_PATH", reg), ("MANIFEST_PATH", man)):
        monkeypatch.setattr(cli, name, path)
    return reg, man


def test_check_passes_on_untouched_synthetic_copies(sandbox):
    assert cli.main(["check"]) == 0


def test_manifest_generation_is_refused_for_false_enforced_claim(sandbox, syn_spec):
    reg, man = sandbox
    man.unlink()
    forged = load_registry(reg)
    _get(forged, "syn_proven")["verification_tests"] = []  # enforced인데 검증 테스트 없음
    reg.write_text(render_yaml(forged, syn_spec), encoding="utf-8")
    assert cli.main(["manifest"]) == 1
    assert not man.exists()  # 생성 거부 — 부분 산출물도 남기지 않음


def test_check_rejects_hand_edited_manifest(sandbox):
    _, man = sandbox
    data = json.loads(man.read_text(encoding="utf-8"))
    data["capabilities"]["syn_pending"].update(status="enforced", effective_status="enforced")
    man.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    assert cli.main(["check"]) == 1


# ── 변이 확인: 머리 검사가 하중을 진다 ────────────────────────────────

STAMP = "spec_header_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""


def test_header_check_is_load_bearing_under_verified_mutation(tmp_path):
    old = "            if cells != TABLE_HEADER:\n"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", "tools/guardrails/spec.py", old,
                                "            if False:\n")
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    node = "tests/test_guardrails_synthetic.py::test_old_or_altered_table_header_is_a_parse_error"
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), "tools.guardrails.spec", node],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"머리 검사 해제 변이가 살아남음\n{out}"
    assert f"FAILED {node}" in out
