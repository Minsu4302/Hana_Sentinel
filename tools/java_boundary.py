"""Burp 확장(Java) 금지선 정적 검사 — (A) §3.1 `java_no_target_send`·`java_loopback_only`·`java_build_egress`,
§3.2 `java_logic_isolation`, 네 키 공통의 우회 차단, 그리고 §3.3 `java_masker_parity`의 정적 하위 검사(관대한 Gson API 금지).

정적 범위: 레포 `burp-extension/`의 Java 소스와 빌드 파일 텍스트. Burp 자체와 바이트코드 수준은 범위 밖이다.
Montoya를 import하지 않는다(N4 — 검사는 텍스트만 본다). 위반은 (키, 코드, 파일, 위치 설명)이며 값·원문을 담지 않는다.

금지 토큰(`java_logic_isolation`)은 Python 정본에서 기계로 뽑는다 — 손 목록이 아니다(`forbidden_tokens`).
면제(R1·R2′)도 정본에서 기계로 뽑는다(`exempt_tokens`) — 손으로 쓴 면제는 없다.
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, get_args, get_origin

PROJECT_DIR: Final = "burp-extension"
MAIN_JAVA: Final = Path("src/main/java")
TEST_JAVA: Final = Path("src/test/java")

NO_TARGET_SEND: Final = "java_no_target_send"
LOOPBACK_ONLY: Final = "java_loopback_only"
LOGIC_ISOLATION: Final = "java_logic_isolation"
BUILD_EGRESS: Final = "java_build_egress"
MASKER_PARITY: Final = "java_masker_parity"
CAPTURE_SELECTED: Final = "java_capture_human_selected"
REQUEST_PARSE: Final = "java_request_parse"

# ── java_build_egress: 정확한 좌표 허용 목록((A) §3.1). 버전 고정은 verification-metadata가 한다.
# error_prone_annotations는 gson이 참조하는 애너테이션이다 — 런타임 불필요를 실측해(2부 PR-1b 0단계 c) compileOnly에만 둔다.
RUNTIME_COORDS: Final = {
    ("compileOnly", "net.portswigger.burp.extensions", "montoya-api"),
    ("implementation", "com.google.code.gson", "gson"),
    ("compileOnly", "com.google.errorprone", "error_prone_annotations"),
}
# verification-metadata에만 오는 parent pom(의존성 선언 아님 — pom 아티팩트만 허용)
PARENT_POMS: Final = {("com.google.code.gson", "gson-parent"), ("com.google.errorprone", "error_prone_parent")}
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
# wrapper 실행 스크립트 — 커밋되어 리뷰된 바이트(.gitattributes: gradlew LF, gradlew.bat CRLF). verify는 실행 전에 대조한다.
GRADLEW_SHA256: Final = "a5a5c199ba02189ae8c46a334223371a20599d9c298ef65e7540ede4a3f72d59"
GRADLEW_BAT_SHA256: Final = "f17917f8dbe61182b149273ee78090fec1197442c3f38276af907bfa5190db16"
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
TARGET_CALLS: Final = re.compile(r"\b(sendRequest\w*|register(?!Unloading)\w*Handler|registerProxy\w*|issueActiveScan|startCrawl|"
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
# 마스커 코어 = 루트.transport.masker 패키지(Burp 없이 실행되는 순수 Java — java.net 0)
CORE_SUBPACKAGE: Final = "transport.masker"
# ── java_masker_parity 정적 하위 검사: 관대한 Gson 진입점·설정(엄격 판정 조합과 §2.10 자체 쓰기만 허용)
LENIENT_JSON: Final = {
    "json_parser": re.compile(r"\bJsonParser\b|\bparseString\b|\bparseReader\b"),
    "gson_builder": re.compile(r"\bGsonBuilder\b"),
    "gson_convert": re.compile(r"\bfromJson\w*\b|\btoJson\w*\b"),
    "set_lenient": re.compile(r"\bsetLenient\b"),
    "lenient_strictness": re.compile(r"\bLENIENT\b|\bLEGACY_STRICT\b"),
}
# ── java_no_target_send 2단계 허용 목록((A) §3.1 v1.52): MontoyaApi의 1단계 접근자 뒤에 올 수 있는 멤버, 금지 멤버
SECOND_LEVEL: Final = {"userInterface": {"registerContextMenuItemsProvider", "registerSuiteTab"},
                       "extension": {"setName", "registerUnloadingHandler"},
                       "logging": {"logToOutput", "logToError"}}
BANNED_MEMBERS: Final = re.compile(r"\.\s*(copyToTempFile|ipAddress|keywordCounts|attributes|annotations|withAnnotations|"
                                   r"timingData|setRequest|setResponse)\s*\(|\.\s*contains\s*\(\s*(?:java\s*\.\s*util\s*\.\s*"
                                   r"regex\s*\.\s*)?Pattern\b")
# ── java_capture_human_selected((A) §2.9·§3.1 v1.52)
PROVIDER: Final = re.compile(r"\bimplements\b[^{]*\bContextMenuItemsProvider\b")
CAPTURE_SOURCES: Final = re.compile(r"\.\s*(?:selectedRequestResponses|messageEditorRequestResponse)\s*\(")
EDITOR_MUTATION: Final = re.compile(r"\.\s*(?:setRequest|setResponse)\s*\(")
OTHER_SOURCES: Final = re.compile(r"\.\s*(?:proxy|siteMap)\s*\(\s*\)|\.\s*history\s*\(|\bregister(?!Unloading)\w*Handler\s*\(")
SCHEDULED: Final = re.compile(r"\bTimer\b|\bScheduledExecutorService\b|\bScheduledThreadPoolExecutor\b|"
                              r"\bnewScheduledThreadPool\b|\bnewSingleThreadScheduledExecutor\b|\.\s*schedule\w*\s*\(")
REPEATER_CHECK: Final = re.compile(r"\bisFromTool\s*\(\s*ToolType\s*\.\s*REPEATER\s*\)")
SELECTION_CALL: Final = re.compile(r"\bSelection\s*\.\s*decide\s*\(")
# 구문 파서 코어 = 루트.capture.core(Burp 없이 실행 — Montoya 0, java.net 0)
PARSE_CORE_SUBPACKAGE: Final = "capture.core"
STRICT_READER: Final = re.compile(r"\.\s*setStrictness\s*\(\s*Strictness\s*\.\s*STRICT\s*\)")
NEW_READER: Final = re.compile(r"\bnew\s+(?:[\w$]+\s*\.\s*)*JsonReader\s*\(")  # 정규 이름 포함


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
    comments: tuple[str, ...] = ()


def lex(text: str) -> Lexed:
    code, full, strings, comments = [], [], [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            comments.append(text[i + 2:n if j < 0 else j])
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            comments.append(text[i + 2:n if j < 0 else j])
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
    return Lexed("".join(code), "".join(full), tuple(strings), tuple(comments))


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


def _model_names(roots: list) -> tuple[set[str], set[str]]:
    """정본 모델(과 하위 모델)의 필드 이름, Literal 문자열 값."""
    from pydantic import BaseModel

    names: set[str] = set()
    literals: set[str] = set()
    seen: set = set()

    def ann(a) -> None:
        if get_origin(a) is Literal:
            literals.update(x for x in get_args(a) if isinstance(x, str))
        elif isinstance(a, type) and issubclass(a, BaseModel):
            model(a)
        else:
            for x in get_args(a):
                ann(x)

    def model(m) -> None:
        if m in seen:
            return
        seen.add(m)
        for name, field in m.model_fields.items():
            names.add(name)
            ann(field.annotation)

    for r in roots:
        model(r)
    return names, literals


def exempt_tokens(tokens: dict[str, tuple[str, ...]] | None = None) -> dict[str, frozenset[str]]:
    """R1 — 면제는 정본에서 기계로 뽑는다(손 목록 없음).
    send: 금지 토큰 ∩ (Envelope 하위 모델의 필드 이름 ∪ Literal 값) → transport 패키지에서만 면제.
    response: 금지 토큰 ∩ ExecutionResponse·AnalysisResult 하위 모델의 '필드 이름' → ui 패키지에서 면제
    (응답 값 — Literal·enum 값 — 은 면제하지 않는다). transport의 응답 파싱 위치는 2부 PR-2에서 정한다."""
    from sentinel import output_schema, schema

    toks = forbidden_tokens() if tokens is None else tokens
    every = {t for values in toks.values() for t in values}
    send_names, send_literals = _model_names([schema.Envelope])
    response_names, _ = _model_names([schema.ExecutionResponse, output_schema.AnalysisResult])
    return {"send": frozenset(every & (send_names | send_literals)), "response": frozenset(every & response_names)}


_IDENTIFIER: Final = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*")


def _member_access(code: str, start: int) -> bool:
    """code[start]에서 시작하는 식별자가 '.이름' 또는 '::이름'(멤버 접근·호출·참조)인가."""
    j = start - 1
    while j >= 0 and code[j].isspace():
        j -= 1
    return (j >= 0 and code[j] == ".") or (j >= 1 and code[j - 1:j + 1] == "::")


def declared_identifiers(files: list) -> set[str]:
    """우리 소스가 선언하는 식별자의 상위 근사 — 멤버 접근이 아닌 자리에 한 번이라도 나오는 모든 식별자.
    선언(클래스·enum 상수·필드·메서드·변수·매개변수)은 항상 멤버 접근이 아닌 자리에 있으므로 빠지지 않는다."""
    out: set[str] = set()
    for f in files:
        for m in _IDENTIFIER.finditer(f.lexed.code):
            if not _member_access(f.lexed.code, m.start()):
                out.add(m.group())
    return out


def _verdict_hit(token: str, f: "JavaFile", declared: set[str]) -> bool:
    """R2′ — 판정 어휘는 문자열 리터럴·주석과 우리 소스가 선언하는 식별자를 검사한다.
    우리 소스에 선언이 없는 외부 API 멤버의 접근·호출(예: `.timeout(`)만 면제한다."""
    if any(_token_hit(token, s) for s in f.lexed.strings) or any(_token_hit(token, c) for c in f.lexed.comments):
        return True
    for m in re.finditer(r"(?<![\w$])" + re.escape(token) + r"(?![\w$])", f.lexed.code):
        if _member_access(f.lexed.code, m.start()) and token not in declared:
            continue  # 외부 API 멤버 — 우리 소스에 선언이 없다
        return True
    return False


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
    files = _require_project(project)
    entries = _entry_points([f for f in files if f.rel.startswith(MAIN_JAVA.as_posix() + "/")])
    root = entries[0].package if len(entries) == 1 else None
    for f in files:
        code = f.lexed.code
        # transport.*는 Burp 없이 실행된다 — Montoya import·정규 이름 사용 0((A) §3.1)
        if _subpackage(f, root) == "transport" and (
                any(name.startswith("burp.") for _s, name in _imports(f)) or re.search(r"\bburp\s*\.\s*api\b", code)):
            out.append(Violation(NO_TARGET_SEND, "transport_montoya_import", f.rel))
        # 2단계 허용 목록: userInterface()·extension()·logging() 바로 뒤의 멤버(. 또는 ::)는 목록 안이어야 한다
        for m in re.finditer(r"\.\s*(userInterface|extension|logging)\s*\(\s*\)", code):
            nxt = re.match(r"\s*(?:\.|::)\s*(\w+)", code[m.end():])
            if not nxt or nxt.group(1) not in SECOND_LEVEL[m.group(1)]:
                out.append(Violation(NO_TARGET_SEND, "montoya_second_level_not_allowed", f"{f.rel}: {m.group(1)}"))
        if BANNED_MEMBERS.search(code):
            out.append(Violation(NO_TARGET_SEND, "montoya_member_banned", f.rel))
        # 마스커 코어는 java.net을 쓰지 않는다(import·정규 이름·정적 import 모두)
        if _in_core(f, root) and re.search(r"\bjava\s*\.\s*net\b", code):
            out.append(Violation(NO_TARGET_SEND, "core_java_net", f.rel))
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
    exempt = exempt_tokens(toks)
    root = entries[0].package if len(entries) == 1 else None
    declared = declared_identifiers(files)
    for f in files:
        sub = _subpackage(f, root)
        skip = (exempt["send"] if sub == "transport" else frozenset()) | (exempt["response"] if sub == "ui" else frozenset())
        for source, values in toks.items():
            for t in values:
                if t in skip:
                    continue  # R1 — 정본에서 뽑은 면제, 해당 패키지에서만
                hit = _verdict_hit(t, f, declared) if source == "verdict" else _token_hit(t, f.text)
                if hit:
                    out.append(Violation(LOGIC_ISOLATION, "forbidden_token_" + source, f.rel))
                    break
    return out


def _subpackage(f: "JavaFile", root: str | None) -> str | None:
    """루트 패키지 바로 아래 패키지 이름(capture/transport/ui …). 루트를 모르거나 밖이면 None."""
    if root is None or not f.package.startswith(root + "."):
        return None
    return f.package[len(root) + 1:].split(".")[0]


def _in_core(f: "JavaFile", root: str | None) -> bool:
    core = f"{root}.{CORE_SUBPACKAGE}" if root else None
    return core is not None and (f.package == core or f.package.startswith(core + "."))


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
    out.extend(wrapper_violations(project))  # auto-download 끔·wrapper 고정값(verify가 실행 전에도 부른다)
    props_p = project / "gradle.properties"
    props = props_p.read_text(encoding="utf-8") if props_p.is_file() else ""
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
            parent_pom = ((c.get("group"), c.get("name")) in PARENT_POMS and bool(arts)
                          and all((a.get("name") or "").endswith(".pom") for a in arts))
            if (c.get("group"), c.get("name")) not in ALLOWED_COMPONENTS and not parent_pom:
                v("metadata_extra_component", f"{c.get('group')}:{c.get('name')}")
        for _conf, g, a, ver in coords:
            if (g, a, ver) not in comps:
                v("metadata_missing", f"{g}:{a}:{ver}")
            elif not comps[(g, a, ver)]:
                v("metadata_no_sha256", f"{g}:{a}:{ver}")
        if root.find("g:trusted-artifacts", ns) is not None or root.find("g:configuration/g:trusted-artifacts", ns) is not None:
            v("metadata_trusted_bypass")
    return out


def _sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def wrapper_violations(project: Path) -> list[Violation]:
    """Gradle을 실행하기 전에 확인할 것: 배포판 URL·sha, wrapper jar·gradlew·gradlew.bat sha, 툴체인 자동 다운로드 끔.
    make verify의 Java 단계가 gradlew를 실행하기 전에 이 함수를 부른다 — 위반이 있으면 실행하지 않는다."""
    out = []
    v = lambda code, where="": out.append(Violation(BUILD_EGRESS, code, where))  # noqa: E731
    props_p = project / "gradle.properties"
    props = props_p.read_text(encoding="utf-8") if props_p.is_file() else ""
    if not any(line.strip().replace(" ", "") == AUTO_DOWNLOAD_OFF for line in props.splitlines()):
        v("toolchain_auto_download", "gradle.properties")
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
    if _sha256(project / "gradle" / "wrapper" / "gradle-wrapper.jar") != GRADLE_WRAPPER_JAR_SHA256:
        v("wrapper_jar_mismatch")
    if _sha256(project / "gradlew") != GRADLEW_SHA256:
        v("gradlew_script_mismatch", "gradlew")
    if _sha256(project / "gradlew.bat") != GRADLEW_BAT_SHA256:
        v("gradlew_script_mismatch", "gradlew.bat")
    return out


def wrapper_distribution_hash(url: str = GRADLE_DISTRIBUTION_URL) -> str:
    """Gradle wrapper가 배포판 캐시 폴더 이름에 쓰는 값: URL 문자열의 MD5를 36진수로 표기."""
    n = int.from_bytes(hashlib.md5(url.encode("utf-8")).digest(), "big")  # noqa: S324 — 보안 용도 아님(폴더 이름 규칙)
    digits, s = "0123456789abcdefghijklmnopqrstuvwxyz", ""
    while n:
        n, r = divmod(n, 36)
        s = digits[r] + s
    return s or "0"


def capture_violations(project: Path) -> list[Violation]:
    """`java_capture_human_selected` — 사람이 컨텍스트 메뉴로 고른 1건만 캡처한다((A) §2.9 v1.52).
    선택 원천(selectedRequestResponses·messageEditorRequestResponse)은 ContextMenuItemsProvider 구현 파일에만 둔다. 편집기 상태
    변경(setRequest·setResponse), 다른 캡처 원천(proxy()·siteMap()·history·register*Handler), 타이머·스케줄러 경로는 0이다.
    provider 파일은 Repeater 출처 판별(isFromTool(ToolType.REPEATER))과 선택 규칙(Selection.decide) 호출을 둔다."""
    out = []
    for f in _require_project(project):
        code = f.lexed.code
        provider = PROVIDER.search(code) is not None
        if CAPTURE_SOURCES.search(code) and not provider:
            out.append(Violation(CAPTURE_SELECTED, "capture_outside_provider", f.rel))
        if EDITOR_MUTATION.search(code):
            out.append(Violation(CAPTURE_SELECTED, "capture_editor_mutation", f.rel))
        if OTHER_SOURCES.search(code):
            out.append(Violation(CAPTURE_SELECTED, "capture_other_source", f.rel))
        if SCHEDULED.search(code):
            out.append(Violation(CAPTURE_SELECTED, "capture_scheduled_path", f.rel))
        if provider:
            if not REPEATER_CHECK.search(code):
                out.append(Violation(CAPTURE_SELECTED, "repeater_check_missing", f.rel))
            if not SELECTION_CALL.search(code):
                out.append(Violation(CAPTURE_SELECTED, "selection_rule_missing", f.rel))
    return out


def request_parse_violations(project: Path) -> list[Violation]:
    """`java_request_parse` 정적 하위 검사 — 구문 파서 코어(루트.capture.core)는 Montoya import 0, java.net 0(Burp 없이 하네스 실행).
    Montoya 이벤트를 다루는 클래스(capture의 provider)는 코어 밖에 둔다."""
    files = _require_project(project)
    entries = _entry_points([f for f in files if f.rel.startswith(MAIN_JAVA.as_posix() + "/")])
    root = entries[0].package if len(entries) == 1 else None
    core = f"{root}.{PARSE_CORE_SUBPACKAGE}" if root else None
    out = []
    for f in files:
        if core is None or not (f.package == core or f.package.startswith(core + ".")):
            continue
        if any(name.startswith("burp.") for _s, name in _imports(f)) or re.search(r"\bburp\s*\.\s*api\b", f.lexed.code):
            out.append(Violation(REQUEST_PARSE, "parse_core_montoya", f.rel))
        if re.search(r"\bjava\s*\.\s*net\b", f.lexed.code):
            out.append(Violation(REQUEST_PARSE, "parse_core_java_net", f.rel))
    return out


def lenient_json_violations(project: Path) -> list[Violation]:
    """`java_masker_parity` 정적 하위 검사 — 엄격 JSON 판정이 Gson 설정에 기대므로 관대한 진입점·설정을 쓰지 않는다.
    JsonParser(parseString·parseReader), GsonBuilder, Gson 변환 메서드(fromJson·toJson — 직렬화는 §2.10 자체 쓰기만),
    setLenient, Strictness.LENIENT·LEGACY_STRICT 금지. JsonReader를 만들면 같은 파일에서 STRICT를 그만큼 설정해야 한다."""
    out = []
    for f in _require_project(project):
        code = f.lexed.code
        for name, rx in LENIENT_JSON.items():
            if rx.search(code):
                out.append(Violation(MASKER_PARITY, "lenient_json_" + name, f.rel))
        if len(NEW_READER.findall(code)) > len(STRICT_READER.findall(code)):
            out.append(Violation(MASKER_PARITY, "json_reader_not_strict", f.rel))
    return out


def all_violations(project: Path) -> list[Violation]:
    return (bypass_violations(project) + no_target_send_violations(project) + loopback_violations(project)
            + logic_isolation_violations(project) + build_egress_violations(project) + lenient_json_violations(project)
            + capture_violations(project) + request_parse_violations(project))
