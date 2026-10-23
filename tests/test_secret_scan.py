"""`secret_scan_hook` — pre-commit 시크릿 스캐너(N7).

가짜 토큰은 전부 런타임에 조립한다 — 이 파일 자체에 비밀값 형태의 리터럴이 없어야
레포 전수 스캔(make verify)을 통과한다. 실데이터 0(N5).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.guardrails import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "tools"))
import secret_scan  # noqa: E402  (단독 스크립트 — 훅과 같은 파일을 직접 검사)

# 패턴 이름 → 런타임 조립한 가짜 비밀값(실제 키 아님)
FAKE_SECRETS = {
    "private_key_block": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "aws_access_key_id": "AKIA" + "Z" * 16,
    "github_token": "ghp" + "_" + "a1B2" * 9,
    "slack_token": "xoxb" + "-" + "1234567890-abcdef",
    "llm_api_key": "sk-" + "ant-" + "Q" * 40,
    "jwt": "eyJ" + "h" * 12 + "." + "eyJ" + "p" * 12 + "." + "s" * 16,
    "bearer_header": "Authorization: " + "Bearer " + "t0k3n" * 5,
    "cookie_header": "Cookie: " + "sessionid=" + "c" * 24,
    "secret_assignment": "api_key" + ' = "' + "dummy-not-a-real-key" + '"',
}

CLEAN_TEXT = """\
import os

# 토큰은 환경변수로만 받는다
token = os.environ["SENTINEL_SHARED_TOKEN"]
password_min_length = 12
headers = {"Authorization": "Bearer <masked>"}
"""


@pytest.mark.parametrize("pattern", sorted(FAKE_SECRETS))
def test_scanner_flags_each_fake_secret_pattern(pattern):
    findings = secret_scan.scan_text("x.txt", f"line one\n{FAKE_SECRETS[pattern]}\n")
    assert pattern in {f.pattern for f in findings}
    assert all(f.line == 2 for f in findings)


def test_scanner_passes_clean_text():
    assert secret_scan.scan_text("clean.py", CLEAN_TEXT) == []


def test_scanner_report_never_echoes_the_secret_value(tmp_path, capsys):
    bad = tmp_path / "leak.txt"
    bad.write_text("\n".join(FAKE_SECRETS.values()) + "\n", encoding="utf-8")
    assert secret_scan.main([str(bad)]) == 1
    out = capsys.readouterr()
    for value in FAKE_SECRETS.values():
        assert value not in out.err + out.out


def test_scanner_requires_arguments():
    assert secret_scan.main([]) == 2


# ── pre-commit 실제 차단(통합) ─────────────────────────────────────

def _git(repo: Path, *args: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                           "-c", "commit.gpgsign=false", *args],
                          cwd=repo, env=env, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture
def hooked_repo(tmp_path):
    """레포의 실제 훅 설정·스캐너를 복사한 임시 git 레포 + pre-commit 설치. 네트워크 불필요."""
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    shutil.copy(REPO_ROOT / ".pre-commit-config.yaml", repo)
    shutil.copy(REPO_ROOT / "tools" / "secret_scan.py", repo / "tools")
    empty_cfg = tmp_path / "empty.gitconfig"
    empty_cfg.write_text("", encoding="utf-8")
    env = {**os.environ,
           # 사용자 전역·시스템 git 설정(hooksPath 등)이 끼어들지 않게 격리
           "GIT_CONFIG_GLOBAL": str(empty_cfg),
           "GIT_CONFIG_NOSYSTEM": "1",
           "PRE_COMMIT_HOME": str(tmp_path / "pre-commit-home"),
           "PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")}
    assert _git(repo, "init", "-q", env=env).returncode == 0
    inst = subprocess.run([sys.executable, "-m", "pre_commit", "install"], cwd=repo, env=env,
                          capture_output=True, text=True)
    assert inst.returncode == 0, inst.stderr
    return repo, env


def _commit_count(repo: Path, env: dict) -> int:
    r = _git(repo, "rev-list", "--count", "--all", env=env)
    return int(r.stdout.strip() or 0) if r.returncode == 0 else 0


def test_precommit_blocks_fake_token_commit(hooked_repo):
    repo, env = hooked_repo
    (repo / "config.py").write_text(f'{FAKE_SECRETS["secret_assignment"]}\n', encoding="utf-8")
    _git(repo, "add", "-A", env=env)
    result = _git(repo, "commit", "-m", "가짜 토큰 커밋 시도", env=env)
    assert result.returncode != 0
    assert "secret_assignment" in result.stdout + result.stderr
    assert _commit_count(repo, env) == 0  # 커밋이 만들어지지 않음


def test_precommit_blocks_each_fake_token_kind(hooked_repo):
    repo, env = hooked_repo
    for i, value in enumerate(FAKE_SECRETS.values()):
        (repo / f"leak_{i}.txt").write_text(value + "\n", encoding="utf-8")
    _git(repo, "add", "-A", env=env)
    result = _git(repo, "commit", "-m", "여러 종류 가짜 토큰", env=env)
    assert result.returncode != 0
    for pattern in FAKE_SECRETS:
        assert pattern in result.stdout + result.stderr
    assert _commit_count(repo, env) == 0


def test_precommit_allows_clean_commit(hooked_repo):
    """대조군: 훅이 '모든 커밋 실패'로 통과하는 가짜 차단이 아님을 확인."""
    repo, env = hooked_repo
    (repo / "clean.py").write_text(CLEAN_TEXT, encoding="utf-8")
    _git(repo, "add", "-A", env=env)
    result = _git(repo, "commit", "-m", "깨끗한 커밋", env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _commit_count(repo, env) == 1


def test_repository_tracked_files_contain_no_secrets():
    r = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "secret_scan.py"), "--all"],
                       cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
