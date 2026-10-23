"""시크릿 스캐너 — pre-commit `repo: local` 훅 + `make verify` 전수 스캔 겸용.

(A) §3.3 `secret_scan_hook` / N7. 외부 다운로드 0(표준 라이브러리만)이며,
pre-commit 통합 테스트가 임시 레포로 복사해 쓰므로 이 파일은 단독 실행 가능해야 한다
(레포 내 다른 모듈 import 금지).

한계(정직 표기): 이 검사는 아래 PATTERNS에 정의된 형태만 탐지한다.
'모든 비밀값의 부재'를 증명하지 않는다 — 불투명한 세션 ID 등은 일반 문자열과 구분 불가.
검출 결과에는 비밀값 원문을 출력하지 않는다(파일·줄·패턴 이름만).

사용:
    python tools/secret_scan.py FILE...     # pre-commit 훅(스테이징 파일)
    python tools/secret_scan.py --all       # git 추적·비무시 파일 전수
종료코드: 0=검출 없음, 1=검출, 2=사용 오류.
"""
from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# 정책에 정의된 패턴만 탐지한다. 패턴 추가는 여기서만.
PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "llm_api_key": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "bearer_header": re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    "cookie_header": re.compile(r"(?i)^\s*(?:set-)?cookie\s*:\s*[^=\s;]+=[^;\s]{16,}"),
    "secret_assignment": re.compile(
        r"(?i)\b[\w-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|shared[_-]?token)"
        r"[\w-]*\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    ),
}

MAX_BYTES = 2 * 1024 * 1024  # 이보다 큰 파일은 텍스트 스캔 대상 아님 → 검출로 취급(fail-closed)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    pattern: str

    def render(self) -> str:
        # 값은 절대 출력하지 않는다.
        return f"{self.path}:{self.line}: [{self.pattern}] 비밀값 의심 패턴"


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append(Finding(path, lineno, name))
    return findings


def scan_file(path: Path) -> list[Finding]:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        return [Finding(str(path), 0, "oversized_file")]
    if b"\x00" in data:
        return []  # 바이너리는 패턴 스캔 대상 아님(캡처물 등은 .gitignore로 차단)
    return scan_text(str(path), data.decode("utf-8", errors="replace"))


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    return [Path(p) for p in out.decode("utf-8").split("\0") if p and Path(p).is_file()]


def main(argv: list[str]) -> int:
    if argv == ["--all"]:
        files = tracked_files()
    elif argv and "--all" not in argv:
        files = [Path(a) for a in argv]
    else:
        print("사용법: secret_scan.py FILE... | --all", file=sys.stderr)
        return 2

    findings = [f for path in files for f in scan_file(path)]
    for f in findings:
        print(f.render(), file=sys.stderr)
    if findings:
        print(f"secret-scan: {len(findings)}건 검출 — 커밋/검증 거부", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
