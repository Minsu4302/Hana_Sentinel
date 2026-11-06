"""`push_requires_verify` — (A) §3.4. verify가 통과한 커밋만 푸시된다. 임시 레포에서 실제 pre-push 훅으로 증명한다.

범위: 클라이언트 훅이라 `git push --no-verify`로 우회할 수 있다(`secret_scan_hook`과 같은 성격). 실수 방지용이다.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import verify_stamp
from tools.mutation_guard import copy_with_mutation
from tests.test_rule_wiring import _run_mutant
from tests.test_secret_scan import _git

REPO_ROOT = Path(__file__).resolve().parents[1]
MARKER = "manifest selfcheck: 활성 module=x keys=1 nodes=1"


@pytest.fixture
def pushable(tmp_path):
    """레포의 실제 훅 설정·검사기를 복사한 임시 레포 + 로컬 bare 원격 + pre-push 훅. 네트워크 불필요."""
    repo, remote = tmp_path / "repo", tmp_path / "remote.git"
    (repo / "tools").mkdir(parents=True)
    shutil.copy(REPO_ROOT / ".pre-commit-config.yaml", repo)
    shutil.copy(REPO_ROOT / ".gitignore", repo)
    shutil.copy(verify_stamp.__file__, repo / "tools")  # 변이 확인이 변이본을 쓰도록 로드된 파일을 복사한다
    shutil.copy(REPO_ROOT / "tools" / "secret_scan.py", repo / "tools")
    empty_cfg = tmp_path / "empty.gitconfig"
    empty_cfg.write_text("", encoding="utf-8")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(empty_cfg), "GIT_CONFIG_NOSYSTEM": "1",
           "PRE_COMMIT_HOME": str(tmp_path / "pre-commit-home"), "PYTHONUTF8": "1",
           "PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")}
    assert _git(tmp_path, "init", "-q", "--bare", str(remote), env=env).returncode == 0
    assert _git(repo, "init", "-q", "-b", "work", env=env).returncode == 0
    assert _git(repo, "remote", "add", "origin", str(remote), env=env).returncode == 0
    inst = subprocess.run([sys.executable, "-m", "pre_commit", "install", "--hook-type", "pre-push"], cwd=repo, env=env,
                          capture_output=True, text=True)
    assert inst.returncode == 0, inst.stderr
    assert _git(repo, "add", "-A", env=env).returncode == 0
    assert _git(repo, "commit", "-q", "--no-verify", "-m", "start", env=env).returncode == 0
    return repo, env


def _push(repo: Path, env: dict) -> subprocess.CompletedProcess:
    return _git(repo, "push", "-q", "origin", "work", env=env)


def _head(repo: Path, env: dict) -> str:
    return _git(repo, "rev-parse", "HEAD", env=env).stdout.strip()


def _stamp(repo: Path, commit: str, **over) -> None:
    doc = {"commit": commit, "exit_code": 0, "selfcheck": MARKER, **over}
    (repo / verify_stamp.STAMP_FILE).write_text(json.dumps(doc), encoding="utf-8")


def _commit(repo: Path, env: dict, name: str = "a.txt") -> None:
    (repo / name).write_text("x\n", encoding="utf-8")
    assert _git(repo, "add", "-A", env=env).returncode == 0
    assert _git(repo, "commit", "-q", "--no-verify", "-m", name, env=env).returncode == 0


# ── 실제 pre-push 훅 ───────────────────────────────────────────────

def test_matching_stamp_on_a_clean_tree_is_pushed(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    assert _push(repo, env).returncode == 0


def test_push_without_a_stamp_is_refused(pushable):
    repo, env = pushable
    r = _push(repo, env)
    assert r.returncode != 0 and "no_stamp" in r.stdout + r.stderr


def test_stamp_of_another_commit_is_refused(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    _commit(repo, env)
    r = _push(repo, env)
    assert r.returncode != 0 and "stamp_commit_differs" in r.stdout + r.stderr


def test_dirty_tree_is_refused(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    (repo / "untracked.txt").write_text("x\n", encoding="utf-8")
    r = _push(repo, env)
    assert r.returncode != 0 and "dirty_tree" in r.stdout + r.stderr


def test_failed_verify_removes_the_old_stamp_so_push_is_refused(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    assert verify_stamp.run_and_stamp(repo, (sys.executable, "-c", "raise SystemExit(1)")) == 1
    r = _push(repo, env)
    assert r.returncode != 0 and "no_stamp" in r.stdout + r.stderr


def test_stamp_file_is_ignored_by_git(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    assert verify_stamp.tree_is_clean(repo)


# ── 스탬프 쓰기 ────────────────────────────────────────────────────

def _passing(marker: str = MARKER) -> tuple[str, ...]:
    return (sys.executable, "-c", f"print({marker!r})")


def test_passing_run_writes_the_commit_and_the_selfcheck_marker(pushable):
    repo, env = pushable
    assert verify_stamp.run_and_stamp(repo, _passing()) == 0
    doc = json.loads((repo / verify_stamp.STAMP_FILE).read_text(encoding="utf-8"))
    assert doc == {"commit": _head(repo, env), "exit_code": 0, "selfcheck": MARKER}


def test_run_without_the_selfcheck_marker_writes_no_stamp(pushable):
    repo, _env = pushable
    assert verify_stamp.run_and_stamp(repo, _passing("no marker")) == 1
    assert not (repo / verify_stamp.STAMP_FILE).exists()


def test_run_on_a_dirty_tree_writes_no_stamp(pushable):
    """검증한 내용과 커밋이 다를 수 있다."""
    repo, _env = pushable
    (repo / "dirty.txt").write_text("x\n", encoding="utf-8")
    assert verify_stamp.run_and_stamp(repo, _passing()) == 0
    assert not (repo / verify_stamp.STAMP_FILE).exists()


@pytest.mark.parametrize("over", [{"exit_code": 1}, {"selfcheck": ""}], ids=["exit_code", "no_marker"])
def test_stamp_without_the_success_fields_is_refused(pushable, over):
    repo, env = pushable
    _stamp(repo, _head(repo, env), **over)
    assert verify_stamp.push_problems(repo, _head(repo, env)) == ["stamp_invalid"]


def test_broken_stamp_is_refused(pushable):
    repo, env = pushable
    (repo / verify_stamp.STAMP_FILE).write_text("not json", encoding="utf-8")
    assert verify_stamp.push_problems(repo, _head(repo, env)) == ["stamp_invalid"]


def test_push_target_is_compared_not_head(pushable):
    repo, env = pushable
    _stamp(repo, _head(repo, env))
    assert verify_stamp.push_problems(repo, "0" * 40) == ["stamp_commit_differs"]


# ── 훅 설치·make verify ────────────────────────────────────────────

def test_installed_hook_is_recognised(pushable):
    repo, _env = pushable
    assert verify_stamp.hook_problems(repo) == []


def test_missing_hook_is_a_problem(pushable):
    repo, _env = pushable
    (repo / ".git" / "hooks" / "pre-push").unlink()
    assert verify_stamp.hook_problems(repo) == ["pre_push_hook_missing"]


def test_foreign_pre_push_hook_is_a_problem(pushable):
    repo, _env = pushable
    (repo / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert verify_stamp.hook_problems(repo) == ["pre_push_hook_missing"]


def test_make_verify_clears_first_checks_the_hook_and_stamps_last():
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    out = subprocess.run(["make", "-n", "verify"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8").stdout
    lines = [line for line in out.splitlines() if "tools" in line]
    assert "verify_stamp.py start" in lines[0] and "verify_stamp.py test" in lines[-1]
    assert any("verify_stamp.py check-hooks" in line for line in lines)


def test_install_hooks_installs_the_pre_push_hook():
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    out = subprocess.run(["make", "-n", "install-hooks"], cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8").stdout
    assert "--hook-type pre-push" in out and "--hook-type pre-commit" in out


# ── 변이 확인 ──────────────────────────────────────────────────────

_V = "tests/test_verify_stamp.py::"
STAMP = ("tools/verify_stamp.py", "tools.verify_stamp")
MUTATIONS = {
    "commit_compare_off": (*STAMP, '    if doc.get("commit") != target:\n', "    if False:\n",
                           [_V + "test_push_target_is_compared_not_head"]),
    "dirty_tree_allowed": (*STAMP, '    problems = [] if tree_is_clean(root) else ["dirty_tree"]\n', "    problems = []\n",
                           [_V + "test_dirty_tree_is_refused"]),
    "old_stamp_kept": (*STAMP, "    clear_stamp(root)\n    process = subprocess.Popen(", "    process = subprocess.Popen(",
                       [_V + "test_failed_verify_removes_the_old_stamp_so_push_is_refused"]),
    "marker_not_required": (*STAMP, "    if not selfcheck:\n", "    if False:\n",
                            [_V + "test_run_without_the_selfcheck_marker_writes_no_stamp"]),
    "dirty_run_stamped": (*STAMP, "    if not tree_is_clean(root):\n        print(", "    if False:\n        print(",
                          [_V + "test_run_on_a_dirty_tree_writes_no_stamp"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_stamp_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
