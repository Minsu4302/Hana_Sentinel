"""verify 스탬프 + pre-push 검사 — (A) §3.4 `push_requires_verify`.

`make verify`가 통과한 커밋만 푸시되게 한다. 사람이 지키는 "실패 시 멈추는 체인" 규칙을 장치로 대신한다.

- `start`: 스탬프를 지운다(verify 맨 앞 — 실패하면 이전 성공 스탬프가 남지 않는다).
- `test`: pytest를 돌리고, 통과했고 selfcheck 활성 표지가 있고 작업 트리가 깨끗할 때만 스탬프를 쓴다.
- `check-hooks`: pre-push 훅이 설치됐는지 본다.
- `check-push`: 푸시 대상 커밋이 스탬프의 커밋과 같고 작업 트리가 깨끗할 때만 통과한다.

표준 라이브러리만 쓴다(훅은 PATH의 python으로 돈다). 범위(정직 표기): 클라이언트 훅이라 `git push --no-verify`로 우회할 수 있다.
실수 방지용이고 서버측 강제가 아니다.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Final

STAMP_FILE: Final = ".verify-stamp"
SELFCHECK_MARKER: Final = "manifest selfcheck: 활성"
PYTEST_COMMAND: Final = (sys.executable, "-m", "pytest", "-p", "tools.guardrails.selfcheck", "--manifest-selfcheck=guardrails.yaml")
PRE_PUSH_MARKER: Final = "--hook-type=pre-push"


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()


def tree_is_clean(root: Path) -> bool:
    return _git(root, "status", "--porcelain") == ""


def clear_stamp(root: Path) -> None:
    (root / STAMP_FILE).unlink(missing_ok=True)


def write_stamp(root: Path, selfcheck: str) -> None:
    doc = {"commit": _git(root, "rev-parse", "HEAD"), "exit_code": 0, "selfcheck": selfcheck}
    (root / STAMP_FILE).write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8")


def run_and_stamp(root: Path, command: tuple[str, ...]) -> int:
    """명령을 돌리고 출력을 그대로 보여 준다. 조건이 모두 맞을 때만 스탬프를 쓴다."""
    clear_stamp(root)
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                               errors="replace")
    selfcheck = ""
    for line in process.stdout:
        print(line, end="", flush=True)
        if SELFCHECK_MARKER in line:
            selfcheck = line.strip()
    code = process.wait()
    if code != 0:
        return code
    if not selfcheck:
        print("verify 스탬프 없음: selfcheck 활성 표지가 없다", file=sys.stderr)
        return 1
    if not tree_is_clean(root):
        print("verify 통과했지만 작업 트리가 깨끗하지 않아 스탬프를 쓰지 않는다(푸시 불가)")
        return 0
    write_stamp(root, selfcheck)
    return 0


def push_problems(root: Path, target: str) -> list[str]:
    """푸시 거부 사유. 비어 있어야 푸시한다."""
    problems = [] if tree_is_clean(root) else ["dirty_tree"]
    path = root / STAMP_FILE
    if not path.exists():
        return [*problems, "no_stamp"]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return [*problems, "stamp_invalid"]
    if not isinstance(doc, dict) or doc.get("exit_code") != 0 or SELFCHECK_MARKER not in str(doc.get("selfcheck")):
        return [*problems, "stamp_invalid"]
    if doc.get("commit") != target:
        problems.append("stamp_commit_differs")
    return problems


def hook_problems(root: Path) -> list[str]:
    hooks = Path(_git(root, "rev-parse", "--git-path", "hooks"))
    path = hooks if hooks.is_absolute() else root / hooks
    hook = path / "pre-push"
    if not hook.exists() or PRE_PUSH_MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        return ["pre_push_hook_missing"]
    return []


def main(argv: list[str]) -> int:
    root = Path.cwd()
    action = argv[0] if argv else ""
    if action == "start":
        clear_stamp(root)
        return 0
    if action == "test":
        return run_and_stamp(root, PYTEST_COMMAND)
    if action == "check-hooks":
        problems = hook_problems(root)
    elif action == "check-push":
        problems = push_problems(root, os.environ.get("PRE_COMMIT_TO_REF") or _git(root, "rev-parse", "HEAD"))
    else:
        print("사용법: verify_stamp.py start|test|check-hooks|check-push", file=sys.stderr)
        return 2
    if problems:
        print("거부: " + " ".join(problems) + " — make verify 뒤에 다시 시도한다(훅이 없으면 make install-hooks)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
