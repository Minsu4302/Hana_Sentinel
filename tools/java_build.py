"""make verify의 Java 단계 - `burp-extension/`을 `gradlew --offline --no-daemon build`로 컴파일·jar.

검증 중 네트워크 0((A) §3.1 `java_build_egress`). Gradle을 실행하기 전에 다음을 먼저 확인하고, 하나라도 어긋나면
gradlew를 실행하지 않고 실패로 끝낸다. 조용히 건너뛰지 않는다.
  1. wrapper 고정값 — distributionUrl·distributionSha256Sum·wrapper jar sha·gradlew/gradlew.bat sha, 툴체인 자동 다운로드 끔
     (`tools.java_boundary.wrapper_violations`). 변조된 실행 스크립트는 실행되기 전에 걸린다.
  2. JDK 21(`JAVA_HOME`, javac 포함).
  3. wrapper 배포판 캐시 — 고정한 distributionUrl에서 나온 폴더(`GRADLE_USER_HOME/wrapper/dists/gradle-9.9.1-bin/<URL 해시>/`)에
     풀린 배포판과 완료 표지(`.ok`)가 있어야 한다. 확인할 수 없으면 실패다(verify는 내려받지 않는다).
첫 다운로드는 개발 PC에서 승인된 좌표만 따로 받는다(docs/burp-extension.md).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # `python tools/java_build.py`로 실행될 때 tools 패키지를 찾게
    sys.path.insert(0, str(REPO_ROOT))

from tools import java_boundary  # noqa: E402

PROJECT = REPO_ROOT / java_boundary.PROJECT_DIR
GRADLE_VERSION = "9.9.1"
JDK_MAJOR = "21"


def preflight(env: dict[str, str], project: Path = PROJECT) -> list[str]:
    """실행 전 확인. 문제 목록(비면 통과). 경로·값은 담지 않는다. wrapper 검사가 맨 앞이다."""
    problems = [f"wrapper 고정값 위반: {v.code}" for v in java_boundary.wrapper_violations(project)]
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
        dist = (Path(gradle_home) / "wrapper" / "dists" / f"gradle-{GRADLE_VERSION}-bin"
                / java_boundary.wrapper_distribution_hash())
        unpacked = dist / f"gradle-{GRADLE_VERSION}" / "bin"
        marker = dist / f"gradle-{GRADLE_VERSION}-bin.zip.ok"
        if not (unpacked.is_dir() and marker.is_file()):
            problems.append(f"고정 distributionUrl의 배포판 캐시 없음(gradle-{GRADLE_VERSION}) - verify는 내려받지 않는다")
    if not (project / "gradlew").is_file():
        problems.append("gradlew 없음")
    return problems


def run(env: dict[str, str], project: Path = PROJECT) -> int:
    problems = preflight(env, project)
    if problems:
        for p in problems:
            print(f"java-build: 실패 - {p}", file=sys.stderr)
        return 1
    gradlew = project / ("gradlew.bat" if os.name == "nt" else "gradlew")
    cmd = [str(gradlew), "--offline", "--no-daemon", "--console=plain", "build"]
    done = subprocess.run(cmd, cwd=project, env=env, shell=False)
    if done.returncode != 0:
        print("java-build: 실패 - gradlew --offline build", file=sys.stderr)
        return 1
    print("java-build: 통과 - gradlew --offline build")
    return 0


def main() -> int:
    return run(dict(os.environ))


if __name__ == "__main__":
    sys.exit(main())
