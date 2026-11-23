"""make verify의 Java 단계 - `burp-extension/`을 `gradlew --offline --no-daemon build`로 컴파일·jar.

검증 중 네트워크 0((A) §3.1 `java_build_egress`): 시작할 때 JDK 21(`JAVA_HOME`)과 wrapper 배포판 캐시
(`GRADLE_USER_HOME/wrapper/dists/gradle-9.9.1-bin/*/gradle-9.9.1`)를 확인하고, 하나라도 없으면 내려받지 않고 실패로 끝낸다.
조용히 건너뛰지 않는다. 첫 다운로드는 개발 PC에서 승인된 좌표만 따로 받는다(docs/burp-extension.md).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "burp-extension"
GRADLE_VERSION = "9.9.1"
JDK_MAJOR = "21"


def preflight(env: dict[str, str]) -> list[str]:
    """실행 전 확인. 문제 목록(비면 통과). 경로·값은 담지 않는다."""
    problems = []
    java_home = env.get("JAVA_HOME", "")
    release = Path(java_home) / "release" if java_home else None
    if not java_home:
        problems.append("JAVA_HOME 없음 - JDK 21이 필요하다")
    elif not release.is_file():
        problems.append("JAVA_HOME에 JDK release 파일이 없음")
    else:
        version = next((line.split("=", 1)[1].strip().strip('"') for line in release.read_text(encoding="utf-8").splitlines()
                        if line.startswith("JAVA_VERSION=")), "")
        if version.split(".")[0] != JDK_MAJOR:
            problems.append(f"JDK 주 버전이 {JDK_MAJOR}가 아님")
        if not any((Path(java_home) / "bin" / name).is_file() for name in ("javac", "javac.exe")):
            problems.append("JAVA_HOME에 javac가 없음(JRE만으로는 빌드할 수 없다)")
    gradle_home = env.get("GRADLE_USER_HOME", "")
    if not gradle_home:
        problems.append("GRADLE_USER_HOME 없음 - wrapper 배포판 캐시 위치를 정해야 한다")
    else:
        dists = Path(gradle_home) / "wrapper" / "dists" / f"gradle-{GRADLE_VERSION}-bin"
        ready = [d for d in dists.glob(f"*/gradle-{GRADLE_VERSION}") if (d / "bin").is_dir()] if dists.is_dir() else []
        if not ready:
            problems.append(f"wrapper 배포판 캐시 없음(gradle-{GRADLE_VERSION}) - verify는 내려받지 않는다")
    if not (PROJECT / "gradlew").is_file():
        problems.append("burp-extension/gradlew 없음")
    return problems


def main() -> int:
    env = dict(os.environ)
    problems = preflight(env)
    if problems:
        for p in problems:
            print(f"java-build: 실패 - {p}", file=sys.stderr)
        return 1
    gradlew = PROJECT / ("gradlew.bat" if os.name == "nt" else "gradlew")
    cmd = [str(gradlew), "--offline", "--no-daemon", "--console=plain", "build"]
    done = subprocess.run(cmd, cwd=PROJECT, env=env, shell=False)
    if done.returncode != 0:
        print("java-build: 실패 - gradlew --offline build", file=sys.stderr)
        return 1
    print("java-build: 통과 - gradlew --offline build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
