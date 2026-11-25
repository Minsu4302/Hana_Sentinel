"""배포 jar 검사 — (A) §3.1 `java_jar_contents`. make verify의 Java 단계가 만든 `burp-extension/build/libs/*.jar`를 본다.

검사(위반은 (코드, 항목 이름)만 — 바이트·값 없음):
- 항목 ⊆ 허용 집합: 우리 main 클래스(sentinel/burp/**.class — 소스가 src/main/java에 있는 최상위 클래스의 것만),
  com/google/gson/**, 정책 리소스, META-INF/MANIFEST.MF, gson 라이선스 원문, 그리고 이들의 상위 디렉터리 항목.
  error_prone 항목·테스트 클래스(동등성 하네스)는 0이어야 한다. 같은 이름이 두 번 나오면 위반.
- 제3자 항목 바이트 = 해시 고정 원본 gson jar(verification-metadata의 sha256)의 같은 항목. com/google/gson/** 집합도 같아야 한다.
- 정책 리소스 바이트 = 레포 정본 파일, 라이선스 항목 바이트 = 레포 `burp-extension/licenses/` 원문.
- 재현 가능 빌드의 정적 조건: 모든 항목의 타임스탬프가 Gradle 고정값(1980-02-01 00:00:00). 두 번 빌드한 해시 비교는 테스트가 한다.
"""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

GSON: Final = ("com.google.code.gson", "gson", "2.15.0")
POLICY_ENTRY: Final = "sentinel/burp/transport/masker/sanitization_policy.json"
LICENSE_DIR: Final = "META-INF/licenses/"
MANIFEST_ENTRY: Final = "META-INF/MANIFEST.MF"
OUR_PREFIX: Final = "sentinel/burp/"
GSON_PREFIX: Final = "com/google/gson/"
FIXED_TIME: Final = (1980, 2, 1, 0, 0, 0)  # Gradle preserveFileTimestamps=false의 고정 시각


@dataclass(frozen=True)
class Violation:
    code: str
    entry: str


def metadata_sha256(project: Path, group: str, name: str, file: str) -> str:
    ns = {"g": "https://schema.gradle.org/dependency-verification"}
    root = ET.fromstring((project / "gradle" / "verification-metadata.xml").read_text(encoding="utf-8"))
    for c in root.findall("g:components/g:component", ns):
        if (c.get("group"), c.get("name")) == (group, name):
            for a in c.findall("g:artifact", ns):
                if a.get("name") == file:
                    return a.find("g:sha256", ns).get("value")
    raise ValueError(f"verification-metadata에 {group}:{name} {file} 없음")


def pinned_gson_jar(project: Path, gradle_home: Path) -> Path:
    """GRADLE_USER_HOME 캐시에서 sha256이 고정값과 같은 gson jar 하나. 없으면 예외(건너뛰지 않는다)."""
    g, a, v = GSON
    want = metadata_sha256(project, g, a, f"{a}-{v}.jar")
    found = [p for p in (gradle_home / "caches" / "modules-2" / "files-2.1" / g / a / v).glob(f"*/{a}-{v}.jar")
             if hashlib.sha256(p.read_bytes()).hexdigest() == want]
    if len(found) != 1:
        raise ValueError("해시가 고정값과 같은 gson jar가 정확히 1개가 아님")
    return found[0]


def built_jar(project: Path) -> Path:
    jars = sorted((project / "build" / "libs").glob("*.jar"))
    if len(jars) != 1:
        raise ValueError(f"build/libs의 jar가 정확히 1개가 아님({len(jars)}개) — make verify의 Java 단계가 먼저")
    return jars[0]


def main_class_roots(project: Path) -> set[str]:
    """src/main/java의 최상위 클래스 경로(확장자 없이, 예: sentinel/burp/transport/masker/Masker)."""
    base = project / "src" / "main" / "java"
    return {p.relative_to(base).with_suffix("").as_posix() for p in base.rglob("*.java") if p.name != "package-info.java"}


def _license_files(project: Path) -> dict[str, bytes]:
    return {LICENSE_DIR + p.name: p.read_bytes() for p in sorted((project / "licenses").glob("*")) if p.is_file()}


def _allowed_file(name: str, roots: set[str], licenses: dict[str, bytes]) -> bool:
    if name in (MANIFEST_ENTRY, POLICY_ENTRY) or name in licenses:
        return True
    if name.startswith(GSON_PREFIX):
        return True
    if name.startswith(OUR_PREFIX) and name.endswith(".class"):
        return name[:-len(".class")].split("$", 1)[0] in roots  # 중첩 클래스는 최상위 소스로
    return False


def violations(jar: Path, project: Path, gson_jar: Path, policy: Path) -> list[Violation]:
    out: list[Violation] = []
    roots = main_class_roots(project)
    licenses = _license_files(project)
    with zipfile.ZipFile(jar) as z, zipfile.ZipFile(gson_jar) as g:
        infos = z.infolist()
        names = [i.filename for i in infos]
        files = [n for n in names if not n.endswith("/")]
        seen: set[str] = set()
        for n in names:
            if n in seen:
                out.append(Violation("duplicate_entry", n))
            seen.add(n)
        parents = {"/".join(f.split("/")[:k]) + "/" for f in files for k in range(1, f.count("/") + 1)}
        for n in names:
            if "errorprone" in n.lower():
                out.append(Violation("error_prone_entry", n))
            if n.endswith("/"):
                if n not in parents:
                    out.append(Violation("entry_not_allowed", n))  # 빈 디렉터리 항목
            elif not _allowed_file(n, roots, licenses):
                out.append(Violation("entry_not_allowed", n))
        for i in infos:
            if i.date_time != FIXED_TIME:
                out.append(Violation("timestamp_not_fixed", i.filename))
        if MANIFEST_ENTRY not in names:
            out.append(Violation("manifest_missing", MANIFEST_ENTRY))
        # 제3자 항목 = 고정 원본의 같은 항목(집합·바이트)
        ours = {n for n in files if n.startswith(GSON_PREFIX)}
        theirs = {n for n in g.namelist() if n.startswith(GSON_PREFIX) and not n.endswith("/")}
        for n in sorted(theirs - ours):
            out.append(Violation("gson_entry_missing", n))
        for n in sorted(ours - theirs):
            out.append(Violation("gson_entry_extra", n))
        for n in sorted(ours & theirs):
            if z.read(n) != g.read(n):
                out.append(Violation("gson_entry_mismatch", n))
        # 정책·라이선스 = 레포 정본
        if POLICY_ENTRY not in names:
            out.append(Violation("policy_missing", POLICY_ENTRY))
        elif hashlib.sha256(z.read(POLICY_ENTRY)).digest() != hashlib.sha256(policy.read_bytes()).digest():
            out.append(Violation("policy_mismatch", POLICY_ENTRY))
        if not licenses:
            out.append(Violation("license_missing", LICENSE_DIR))  # 제3자(gson)를 묶어 배포하므로 라이선스 원문이 있어야 한다
        for name, data in licenses.items():
            if name not in names:
                out.append(Violation("license_missing", name))
            elif z.read(name) != data:
                out.append(Violation("license_mismatch", name))
    return out


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
