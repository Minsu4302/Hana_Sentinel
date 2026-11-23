"""Burp 확장(Java) 금지선 정적 검사 — (A) §3.1 `java_no_target_send`·`java_loopback_only`·`java_build_egress`,
§3.2 `java_logic_isolation`, 그리고 네 키 공통의 우회 차단.

정적 범위: 레포 `burp-extension/`의 Java 소스와 빌드 파일 텍스트. Burp 자체와 바이트코드 수준은 범위 밖이다.
Montoya를 import하지 않는다(N4 — 검사는 텍스트만 본다). 위반은 (키, 코드, 파일, 위치 설명)이며 값·원문을 담지 않는다.

금지 토큰(`java_logic_isolation`)은 Python 정본에서 기계로 뽑는다 — 손 목록이 아니다(`forbidden_tokens`).
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Final, get_args

PROJECT_DIR: Final = "burp-extension"
MAIN_JAVA: Final = Path("src/main/java")
TEST_JAVA: Final = Path("src/test/java")

NO_TARGET_SEND: Final = "java_no_target_send"
LOOPBACK_ONLY: Final = "java_loopback_only"
LOGIC_ISOLATION: Final = "java_logic_isolation"
BUILD_EGRESS: Final = "java_build_egress"

# ── java_build_egress: 정확한 좌표 허용 목록((A) §3.1). 버전은 후보 — 구현 PR에서 고정하며, 지금 고정된 것은 montoya-api뿐.
RUNTIME_COORDS: Final = {
    ("compileOnly", "net.portswigger.burp.extensions", "montoya-api"),
    ("implementation", "com.google.code.gson", "gson"),
    ("implementation", "com.google.errorprone", "error_prone_annotations"),
}
TEST_COORDS: Final = {
    ("testImplementation", "org.junit.jupiter", "junit-jupiter"),
    ("testRuntimeOnly", "org.junit.platform", "junit-platform-launcher"),
}
ALLOWED_COORDS: Final = RUNTIME_COORDS | TEST_COORDS
ALLOWED_COMPONENTS: Final = {(g, a) for _c, g, a in ALLOWED_COORDS}
ALLOWED_PLUGINS: Final = {"java"}
BUILD_FILES: Final = {"build.gradle", "settings.gradle"}
# 공식 체크섬(services.gradle.org) — 리뷰를 거친 고정값. 바꾸려면 이 표와 (A)를 함께 고친다.
GRADLE_DISTRIBUTION_URL: Final = "https://services.gradle.org/distributions/gradle-9.9.1-bin.zip"
GRADLE_DISTRIBUTION_SHA256: Final = "d8a18a7a841dd5df825d35a685fad6f2d7f12ac0c280e57b67c27b4a520ba228"
GRADLE_WRAPPER_JAR_SHA256: Final = "621008afc4f5d59357fcf06ffa644dd5aade5e091bdc363742710445f73cdaf8"
AUTO_DOWNLOAD_OFF: Final = "org.gradle.java.installations.auto-download=false"

# ── java_no_target_send: MontoyaApi에서 시작하는 호출 허용 목록 + import 허용 목록(2부의 요청/응답 읽기 포함)
MONTOYA_CALLS: Final = {"extension", "logging", "userInterface"}
MONTOYA_IMPORT_EXACT: Final = {"burp.api.montoya.BurpExtension", "burp.api.montoya.MontoyaApi"}
MONTOYA_IMPORT_PREFIX: Final = ("burp.api.montoya.logging.", "burp.api.montoya.extension.", "burp.api.montoya.ui.",
                                "burp.api.montoya.http.message.", "burp.api.montoya.core.")
# 이름만으로 위반인 호출(수신자와 무관 — 별칭·체인 우회 차단). 인자 없는 접근자는 대상 송신·자동 캡처 도구다.
TARGET_ACCESSORS: Final = ("http", "repeater", "intruder", "scanner", "collaborator", "persistence", "proxy",
                           "burpSuite", "siteMap", "scope", "websockets", "organizer", "comparer", "decoder", "bambda",
                           "project", "utilities")
TARGET_CALLS: Final = re.compile(r"\b(sendRequest\w*|register\w*Handler|registerProxy\w*|issueActiveScan|startCrawl|"
                                 r"sendToRepeater|sendToIntruder|sendToOrganizer|sendToComparer|createBurpCollaboratorClient)\s*\(")
# ── 공통 우회 차단
BYPASS: Final = {
    "reflection": re.compile(r"\bjava\s*\.\s*lang\s*\.\s*reflect\b|\bget(?:Declared)?(?:Method|Methods|Field|Fields|Constructor|"
                             r"Constructors)\s*\(|\.\s*invoke\s*\(|\bsetAccessible\b"),
    "class_for_name": re.compile(r"\bClass\s*\.\s*forName\b|\bforName\s*\("),
    "method_handles": re.compile(r"\bMethodHandles?\b|\bjava\s*\.\s*lang\s*\.\s*invoke\b"),
    "service_loader": re.compile(r"\bServiceLoader\b"),
    "custom_classloader": re.compile(r"\b\w*ClassLoader\b|\bdefineClass\b"),
    "runtime_exec": re.compile(r"\bRuntime\s*\.\s*getRuntime\b|\bRuntime\b"),
    "process_builder": re.compile(r"\bProcessBuilder\b|\bProcessHandle\b"),
}
# ── java_loopback_only
NET_TOKENS: Final = re.compile(r"\bjava\s*\.\s*net\b|\bHttpClient\b|\bHttpRequest\s*\.\s*newBuilder\b|\bURLConnection\b|"
                               r"\bHttpURLConnection\b|\bopenConnection\b|\bnew\s+URL\s*\(|\bSocket\w*\b|\b\w*SocketChannel\b|"
                               r"\bInet\w*Address\b|\bURI\s*\.\s*create\b|\bnew\s+URI\s*\(|\bokhttp3?\b|\borg\s*\.\s*apache\s*\.\s*http\b")
RAW_NET: Final = re.compile(r"\bURLConnection\b|\bHttpURLConnection\b|\bopenConnection\b|\bnew\s+URL\s*\(|\bSocket\w*\b|"
                            r"\b\w*SocketChannel\b|\bokhttp3?\b|\borg\s*\.\s*apache\s*\.\s*http\b")
LOOPBACK_PREFIX: Final = "http://127.0.0.1:"
ALLOWED_PACKAGES: Final = ("capture", "transport", "ui")


@dataclass(frozen=True)
class Violation:
    key: str
    code: str
    where: str


class JavaScanError(Exception):
    """검사 대상이 없거나 읽을 수 없다 — 통과가 아니라 오류다."""


# ────────────────────────────── Java 어휘 분리
@dataclass(frozen=True)
class Lexed:
    code: str              # 주석 제거, 문자열·문자 리터럴 내용은 공백으로(따옴표는 유지)
    with_strings: str      # 주석만 제거
    strings: tuple[str, ...]


def lex(text: str) -> Lexed:
    code, full, strings = [], [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            code.append(" ")
            full.append(" ")
            continue
        if text.startswith('"""', i):
            j = text.find('"""', i + 3)
            end = n if j < 0 else j + 3
            body = text[i + 3:end - 3 if j >= 0 else n]
            strings.append(body)
            code.append('""' + " " * len(body) + '""')
            full.append(text[i:end])
            i = end
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            body = text[i + 1:j]
            if c == '"':
                strings.append(body)
            code.append(c + " " * len(body) + c)
            full.append(text[i:j + 1])
            i = j + 1
            continue
        code.append(c)
        full.append(c)
        i += 1
    return Lexed("".join(code), "".join(full), tuple(strings))


def _strip_gradle_comments(text: str) -> str:
    return lex(text).with_strings


# ────────────────────────────── 금지 토큰(Python 정본에서 기계 추출)
def forbidden_tokens() -> dict[str, tuple[str, ...]]:
    """출처별 금지 토큰. 손 목록이 아니다 — 정본 모듈의 열거·템플릿·규칙 목록에서 뽑는다."""
    from sentinel import output_schema, schema
    from sentinel.pipeline import llm_prompt, output_gate, rule_engine

    category = tuple(get_args(output_schema.Category))
    verdict: list[str] = []
    for lit in (output_schema.FindingStatus, output_schema.ClaimBasis, output_schema.Corroboration,
                output_schema.AnomalyFlag, schema.ExecutionResponse.model_fields["analysis_status"].annotation):
        verdict.extend(get_args(lit))
    verdict.extend(["ok", "rejected"])  # llm_outcome의 성공·거부 값(output_gate._llm_result)
    verdict.extend(f"failed:{r}" for r in output_schema.LLM_FAILURE_REASONS)  # llm_outcome의 실패 값
    verdict.extend(output_schema.LLM_FAILURE_REASONS)
    verdict.extend(output_gate.REASON_CODES)  # 출력 거부 사유 코드
    phrases = []
    for line in llm_prompt.TEMPLATE_TEXT.splitlines():
        s = line.strip().lstrip("-").strip()
        if len(s.split()) >= 4 and "{" not in s:
            phrases.append(s)
    rules = tuple(f.__name__ for f in rule_engine.RULES)
    return {"category": tuple(dict.fromkeys(category)), "verdict": tuple(dict.fromkeys(verdict)),
            "prompt_phrase": tuple(dict.fromkeys(phrases)), "rule_function": tuple(dict.fromkeys(rules))}


def _token_hit(token: str, text: str) -> bool:
    if " " in token:  # 프롬프트 문구 — 부분 문자열
        return token in text
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])", text) is not None


# ────────────────────────────── 소스 열거
@dataclass(frozen=True)
class JavaFile:
    rel: str
    package: str
    text: str
    lexed: Lexed


def _java_files(project: Path) -> list[JavaFile]:
    files = []
    for p in sorted(project.rglob("*.java")):
        rel = p.relative_to(project).as_posix()
        if rel.startswith(("build/", ".gradle/")):
            continue
        text = p.read_text(encoding="utf-8")
        lexed = lex(text)
        m = re.search(r"^\s*package\s+([\w.]+)\s*;", lexed.code, re.M)
        files.append(JavaFile(rel, m.group(1) if m else "", text, lexed))
    return files


def _require_project(project: Path) -> list[JavaFile]:
    if not project.is_dir():
        raise JavaScanError(f"검사 대상 없음: {project}")
    files = _java_files(project)
    if not any(f.rel.startswith(MAIN_JAVA.as_posix() + "/") for f in files):
        raise JavaScanError("src/main/java에 Java 소스가 없음 — 빈 대상은 통과가 아니다")
    return files


# ────────────────────────────── 공통 우회 차단
def bypass_violations(project: Path) -> list[Violation]:
    out = []
    for f in _require_project(project):
        for code, rx in BYPASS.items():
            if rx.search(f.lexed.code):
                out.append(Violation(NO_TARGET_SEND, "bypass_" + code, f.rel))
    return out


# ────────────────────────────── java_no_target_send
def _imports(f: JavaFile) -> list[tuple[bool, str]]:
    return [(bool(m.group(1)), m.group(2).replace(" ", "")) for m in
            re.finditer(r"^\s*import\s+(static\s+)?([\w.\s]+?(?:\.\*)?)\s*;", f.lexed.code, re.M)]


def no_target_send_violations(project: Path) -> list[Violation]:
    out = []
    for f in _require_project(project):
        code = f.lexed.code
        for static, name in _imports(f):
            if not name.startswith("burp."):
                continue
            ok = (not static and not name.endswith(".*")
                  and (name in MONTOYA_IMPORT_EXACT or name.startswith(MONTOYA_IMPORT_PREFIX)))
            if not ok:
                out.append(Violation(NO_TARGET_SEND, "montoya_import_not_allowed", f"{f.rel}: {name}"))
        if re.search(r"\bburp\s*\.\s*api\b", re.sub(r"^\s*import\s+[^;]+;", "", code, flags=re.M)):
            out.append(Violation(NO_TARGET_SEND, "montoya_fqn_use", f.rel))  # import 없이 정규 이름으로 우회
        api_names = set(re.findall(r"\bMontoyaApi\s+(\w+)", code))
        for name in api_names:
            # `name` 또는 `this.name`의 모든 출현. 허용: 선언 / 허용 목록 호출 / this.<MontoyaApi 필드> = <MontoyaApi 이름>;
            for m in re.finditer(r"(?<![\w.])(this\s*\.\s*)?" + re.escape(name) + r"\b", code):
                before = code[max(0, m.start() - 60):m.start()]
                after = code[m.end():m.end() + 80]
                if not m.group(1) and re.search(r"\bMontoyaApi\s+$", before):
                    continue  # 선언
                call = re.match(r"\s*\.\s*(\w+)\s*\(", after)
                if call:
                    if call.group(1) not in MONTOYA_CALLS:
                        out.append(Violation(NO_TARGET_SEND, "montoya_call_not_allowed", f"{f.rel}: {call.group(1)}"))
                    continue
                assign = re.match(r"\s*=\s*(\w+)\s*;", after)
                if m.group(1) and assign and assign.group(1) in api_names:
                    continue  # this.<필드> = <MontoyaApi 이름>; 의 왼쪽
                field = re.search(r"\bthis\s*\.\s*(\w+)\s*=\s*$", before)
                if not m.group(1) and field and field.group(1) in api_names and re.match(r"\s*;", after):
                    continue  # 같은 문장의 오른쪽
                out.append(Violation(NO_TARGET_SEND, "montoya_api_escapes", f"{f.rel}: {name}"))
        for m in re.finditer(r"\.\s*(\w+)\s*\(\s*\)", code):
            if m.group(1) in TARGET_ACCESSORS:
                out.append(Violation(NO_TARGET_SEND, "target_tool_accessor", f"{f.rel}: {m.group(1)}"))
        for m in TARGET_CALLS.finditer(code):
            out.append(Violation(NO_TARGET_SEND, "target_send_call", f"{f.rel}: {m.group(1)}"))
    return out


# ────────────────────────────── java_logic_isolation
def _entry_points(files: list[JavaFile]) -> list[JavaFile]:
    return [f for f in files if re.search(r"\bimplements\b[^{]*\bBurpExtension\b", f.lexed.code)]


def logic_isolation_violations(project: Path, tokens: dict[str, tuple[str, ...]] | None = None) -> list[Violation]:
    files = _require_project(project)
    out = []
    main = [f for f in files if f.rel.startswith(MAIN_JAVA.as_posix() + "/")]
    for f in files:
        base = next((b for b in (MAIN_JAVA, TEST_JAVA) if f.rel.startswith(b.as_posix() + "/")), None)
        if base is None:
            out.append(Violation(LOGIC_ISOLATION, "java_outside_source_sets", f.rel))
            continue
        if f.package.replace(".", "/") != Path(f.rel).parent.relative_to(base).as_posix():
            out.append(Violation(LOGIC_ISOLATION, "package_dir_mismatch", f.rel))
    entries = _entry_points(main)
    if len(entries) != 1:
        out.append(Violation(LOGIC_ISOLATION, "entry_point_count", f"진입점 {len(entries)}개"))
    if entries:
        root = entries[0].package
        for f in main:
            if f.package == root:
                if f is not entries[0] and not f.rel.endswith("/package-info.java"):
                    out.append(Violation(LOGIC_ISOLATION, "root_package_extra_class", f.rel))
                continue
            sub = f.package[len(root) + 1:].split(".")[0] if f.package.startswith(root + ".") else None
            if sub not in ALLOWED_PACKAGES:
                out.append(Violation(LOGIC_ISOLATION, "package_not_allowed", f"{f.rel}: {f.package}"))
        types = len(re.findall(r"\b(?:class|interface|enum|record)\s+\w+", entries[0].lexed.code))
        if types != 1:
            out.append(Violation(LOGIC_ISOLATION, "entry_point_extra_types", entries[0].rel))
    toks = forbidden_tokens() if tokens is None else tokens
    for f in files:
        for source, values in toks.items():
            for t in values:
                if _token_hit(t, f.text):
                    out.append(Violation(LOGIC_ISOLATION, "forbidden_token_" + source, f.rel))
                    break
    return out


# ────────────────────────────── java_loopback_only
def _first_arg_literal(full: str, start: int) -> str | None:
    """`(` 다음 첫 인자가 문자열 리터럴로 시작하면 그 내용, 아니면 None."""
    m = re.match(r"\s*\"((?:[^\"\\\n]|\\.)*)\"", full[start:])
    return m.group(1) if m else None


def loopback_violations(project: Path) -> list[Violation]:
    files = _require_project(project)
    entries = _entry_points([f for f in files if f.rel.startswith(MAIN_JAVA.as_posix() + "/")])
    root = entries[0].package if len(entries) == 1 else None
    out = []
    for f in files:
        code, full = f.lexed.code, f.lexed.with_strings
        in_transport = root is not None and (f.package == f"{root}.transport" or f.package.startswith(f"{root}.transport."))
        if not NET_TOKENS.search(code):
            continue
        if not in_transport:
            out.append(Violation(LOOPBACK_ONLY, "client_outside_transport", f.rel))
            continue
        if RAW_NET.search(code):
            out.append(Violation(LOOPBACK_ONLY, "raw_or_third_party_client", f.rel))
        if re.search(r"\bHttpClient\s*\.\s*newHttpClient\b", code):
            out.append(Violation(LOOPBACK_ONLY, "default_client", f.rel))
        builders = len(re.findall(r"\bHttpClient\s*\.\s*newBuilder\s*\(", code))
        if builders:
            if len(re.findall(r"\.\s*proxy\s*\(\s*HttpClient\s*\.\s*Builder\s*\.\s*NO_PROXY\s*\)", code)) < builders:
                out.append(Violation(LOOPBACK_ONLY, "proxy_not_disabled", f.rel))
            if len(re.findall(r"\.\s*followRedirects\s*\(\s*HttpClient\s*\.\s*Redirect\s*\.\s*NEVER\s*\)", code)) < builders:
                out.append(Violation(LOOPBACK_ONLY, "redirect_not_disabled", f.rel))
        if re.search(r"\bProxySelector\b|\bRedirect\s*\.\s*(?:ALWAYS|NORMAL)\b", code):
            out.append(Violation(LOOPBACK_ONLY, "proxy_or_redirect_enabled", f.rel))
        for m in re.finditer(r"\bURI\s*\.\s*create\s*\(|\bnew\s+URI\s*\(", full):
            lit = _first_arg_literal(full, m.end())
            # 첫 인자는 "http://127.0.0.1:" 로 시작하는 리터럴이어야 한다(변수·다른 호스트 금지)
            if lit is None or not re.fullmatch(re.escape(LOOPBACK_PREFIX) + r"\d*(?:/[\w/\-.]*)?", lit):
                out.append(Violation(LOOPBACK_ONLY, "destination_not_loopback_literal", f.rel))
        for s in f.lexed.strings:
            # userinfo(@)·다른 스킴/호스트·localhost는 어느 리터럴에도 두지 않는다
            if re.search(r"localhost|@|://", s, re.I) and not re.fullmatch(
                    re.escape(LOOPBACK_PREFIX) + r"\d*(?:/[\w/\-.]*)?", s):
                out.append(Violation(LOOPBACK_ONLY, "non_loopback_url_literal", f.rel))
                break
    return out


# ────────────────────────────── java_build_egress
_DEP_LINE = re.compile(r"^\s*(\w+)\s*\(?\s*(.+?)\s*\)?\s*$")


def _block(text: str, name: str) -> list[str]:
    """`name { ... }` 블록 본문들(중괄호 균형)."""
    blocks = []
    for m in re.finditer(r"\b" + name + r"\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        blocks.append(text[m.end():i - 1])
    return blocks


def _declared_coords(build: str) -> tuple[list[tuple[str, str, str, str]], list[str]]:
    coords, bad = [], []
    for body in _block(build, "dependencies"):
        for raw in body.splitlines():
            line = raw.strip()
            if not line:
                continue
            m = _DEP_LINE.match(line)
            notation = m.group(2) if m else line
            s = re.fullmatch(r"['\"]([\w.\-]+):([\w.\-]+):([^'\"]+)['\"]", notation.strip())
            if not m or not s:
                bad.append(line)
                continue
            coords.append((m.group(1), s.group(1), s.group(2), s.group(3)))
    return coords, bad


def build_egress_violations(project: Path) -> list[Violation]:
    if not project.is_dir():
        raise JavaScanError(f"검사 대상 없음: {project}")
    out = []
    v = lambda code, where="": out.append(Violation(BUILD_EGRESS, code, where))  # noqa: E731
    for p in project.rglob("*"):
        rel = p.relative_to(project).as_posix()
        if rel.startswith(("build/", ".gradle/")) or not p.is_file():
            continue
        if (p.suffix in (".gradle", ".kts") and rel not in BUILD_FILES) or rel.startswith(("buildSrc/", "gradle/init")):
            v("extra_build_script", rel)
    build_p, settings_p = project / "build.gradle", project / "settings.gradle"
    if not build_p.is_file() or not settings_p.is_file():
        raise JavaScanError("build.gradle·settings.gradle이 없음")
    build = _strip_gradle_comments(build_p.read_text(encoding="utf-8"))
    settings = _strip_gradle_comments(settings_p.read_text(encoding="utf-8"))
    # 플러그인: 코어 'java'만, 버전 지정(외부 플러그인)·apply plugin·buildscript 금지
    for body in _block(build, "plugins"):
        ids = r"\bid\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?(\s*version\b[^\n]*)?"
        for m in re.finditer(ids, body):
            if m.group(1) not in ALLOWED_PLUGINS or m.group(2):
                v("plugin_not_allowed", m.group(1))
        if re.sub(ids, "", body).strip():
            v("plugin_not_allowed", "plugins 블록의 id 밖 선언")
    if re.search(r"\bapply\s+plugin\b|\bbuildscript\s*\{|\bapply\s*\(\s*from\b|\bapply\s+from\b", build):
        v("plugin_not_allowed", "apply/buildscript")
    # 저장소: build.gradle의 mavenCentral() 하나뿐. 그 밖의 저장소·플러그인 저장소·툴체인 resolver 0
    repos = _block(build, "repositories")
    repo_text = " ".join(repos)
    if len(repos) != 1 or re.sub(r"\s+", "", repo_text) != "mavenCentral()":
        v("extra_repository", "build.gradle repositories")
    outside = build
    for body in repos:
        outside = outside.replace(body, "")
    if re.search(r"\b(?:maven|ivy)\s*[({]|\b(?:google|jcenter|mavenLocal|gradlePluginPortal|flatDir)\s*\(|\burl\s*[=(]", outside):
        v("extra_repository", "build.gradle 저장소 블록 밖")
    if re.search(r"\b(?:pluginManagement|dependencyResolutionManagement|repositories|plugins|includeBuild|sourceControl)\b",
                 settings):
        v("plugin_repository", "settings.gradle")
    if re.search(r"foojay|toolchainManagement|\btoolchain\b|org\.gradle\.toolchains", build + settings, re.I):
        v("toolchain_resolver", "build/settings")
    props_p = project / "gradle.properties"
    props = props_p.read_text(encoding="utf-8") if props_p.is_file() else ""
    if not any(line.strip().replace(" ", "") == AUTO_DOWNLOAD_OFF for line in props.splitlines()):
        v("toolchain_auto_download", "gradle.properties")
    if re.search(r"^\s*systemProp\.(?:https?\.proxy|gradle\.wrapperUser)", props, re.M) or "org.gradle.toolchains" in props:
        v("toolchain_resolver", "gradle.properties")
    # 좌표 허용 목록(부분집합), 동적 버전 금지
    coords, bad = _declared_coords(build)
    for line in bad:
        v("dependency_notation", line[:60])
    for conf, g, a, ver in coords:
        if (conf, g, a) not in ALLOWED_COORDS:
            v("coordinate_not_allowed", f"{conf} {g}:{a}")
        if re.search(r"[+\[\](),]|latest\.|SNAPSHOT", ver):
            v("dynamic_version", f"{g}:{a}")
    # verification metadata: 메타데이터 검증 켜짐, 선언 좌표 전부 sha256, 허용 밖 컴포넌트 0
    meta_p = project / "gradle" / "verification-metadata.xml"
    if not meta_p.is_file():
        v("metadata_missing", "gradle/verification-metadata.xml")
    else:
        ns = {"g": "https://schema.gradle.org/dependency-verification"}
        root = ET.fromstring(meta_p.read_text(encoding="utf-8"))
        if (root.findtext("g:configuration/g:verify-metadata", namespaces=ns) or "").strip() != "true":
            v("metadata_verify_off")
        comps = {}
        for c in root.findall("g:components/g:component", ns):
            arts = c.findall("g:artifact", ns)
            comps[(c.get("group"), c.get("name"), c.get("version"))] = (
                bool(arts) and all(a.find("g:sha256", ns) is not None for a in arts))
            if (c.get("group"), c.get("name")) not in ALLOWED_COMPONENTS:
                v("metadata_extra_component", f"{c.get('group')}:{c.get('name')}")
        for _conf, g, a, ver in coords:
            if (g, a, ver) not in comps:
                v("metadata_missing", f"{g}:{a}:{ver}")
            elif not comps[(g, a, ver)]:
                v("metadata_no_sha256", f"{g}:{a}:{ver}")
        if root.find("g:trusted-artifacts", ns) is not None or root.find("g:configuration/g:trusted-artifacts", ns) is not None:
            v("metadata_trusted_bypass")
    # wrapper: 배포판 URL·sha 고정, wrapper jar 공식 체크섬
    wp = project / "gradle" / "wrapper" / "gradle-wrapper.properties"
    wprops = {}
    if wp.is_file():
        for line in wp.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, _, val = line.partition("=")
                wprops[k.strip()] = val.strip().replace("\\:", ":")
    if wprops.get("distributionUrl") != GRADLE_DISTRIBUTION_URL:
        v("wrapper_url", "distributionUrl")
    if "distributionSha256Sum" not in wprops:
        v("wrapper_sha_missing")
    elif wprops["distributionSha256Sum"] != GRADLE_DISTRIBUTION_SHA256:
        v("wrapper_sha_mismatch")
    jar = project / "gradle" / "wrapper" / "gradle-wrapper.jar"
    if not jar.is_file() or hashlib.sha256(jar.read_bytes()).hexdigest() != GRADLE_WRAPPER_JAR_SHA256:
        v("wrapper_jar_mismatch")
    return out


def all_violations(project: Path) -> list[Violation]:
    return (bypass_violations(project) + no_target_send_violations(project) + loopback_violations(project)
            + logic_isolation_violations(project) + build_egress_violations(project))
