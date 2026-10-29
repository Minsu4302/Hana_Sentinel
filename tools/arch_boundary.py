"""아키텍처 경계 정적 검사 — 패키지의 금지 import 탐지.

(A) §3.2 `engine_burp_isolation`(N4) / §3.1 `no_autonomous_send`(N2, §1.3 ⓐ) / §3.2 `engine_tools_isolation`·
`engine_no_rawtransaction`·`masker_independence` / §3.1 `masker_no_send` / §3.5 `label_isolation`.
소스의 AST를 읽어 (a) Burp/Montoya, (b) HTTP 송신·소켓 송신 모듈·심볼, (c) tools/ 패키지, (d) 마스킹 전 원본 타입
(RawTransaction 계열 — 위치와 무관하게 이름으로, 정의 포함), (e) 엔진 검증 파이프라인(`sentinel.pipeline`)의
import를 찾고, (f) 평가 라벨 경로(문자열 상수의 'datasets'·'labels.json', LabelFile 이름 참조 — 독스트링 제외)를 찾아
종류별로 분류한다. 어떤 종류가 금지인지는 대상 패키지마다 다르다(엔진: a·b·c·d·f / 마스커: b·e) —
호출하는 쪽이 종류로 거른다.
정적 검증이 불가능한 동적 import(비리터럴 인자)와 exec/eval은 우회 경로이므로 그 자체로 위반 처리(fail-closed).
검사 대상이 비었거나 파싱할 수 없으면 '위반 없음'이 아니라 오류로 멈춘다.

한계(정직 표기): 엔진 소스의 직접 import만 본다. 제3자 패키지가 내부에서 송신하는 전이 의존성,
런타임 조립 문자열, `loop.create_connection`처럼 수신 객체를 정적으로 알 수 없는 호출은 잡지 못한다
— 의존성 egress는 W1-02(`egress_static_check`·`egress_runtime_block`)의 책임이다.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

BURP = "burp_isolation"
SEND = "autonomous_send"
DYNAMIC = "dynamic_import"
TOOLS = "tools_import"            # 엔진 → tools/ (engine_tools_isolation)
RAW = "raw_transaction"           # 엔진 → 마스킹 전 원본 타입, 위치 무관 (engine_no_rawtransaction)
PIPELINE = "engine_pipeline"      # 마스커 → 엔진 검증 파이프라인 (masker_independence)
LABELS = "eval_label_path"        # 엔진 → 평가 라벨 데이터 (label_isolation) — 정적 범위만

# (a) Burp/Montoya — 이름 경로의 어느 구성요소든 해당하면 위반
BURP_COMPONENTS = ("burp", "montoya", "portswigger")

# (b) HTTP 송신·소켓 송신 모듈(자신 또는 하위 모듈)
SEND_MODULES = (
    "socket", "ssl", "socketserver", "selectors",
    "http.client", "http.server", "urllib.request", "xmlrpc.client", "xmlrpc.server",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "nntplib",
    "requests", "httpx", "aiohttp", "urllib3", "httplib2", "pycurl", "websocket", "websockets",
    "grpc", "paramiko", "asyncssh", "twisted", "tornado",
)
# 패키지는 허용하되 송신 심볼만 금지하는 경우(예: `from http import HTTPStatus`는 허용)
SEND_SYMBOLS = {
    "http": {"client", "server"},
    "urllib": {"request"},
    "xmlrpc": {"client", "server"},
    "asyncio": {"open_connection", "open_unix_connection", "start_server", "start_unix_server"},
}
DYNAMIC_IMPORTERS = {"__import__", "import_module"}

# (c) tools/ 최상위 패키지
TOOLS_PACKAGE = "tools"
# (d) 마스킹 전 원본 타입((A) §2.7) — 이름으로 잡는다. 타입이 tools/ 밖(예: 엔진 공용 모듈)으로 옮겨져도 import·속성 접근·
#     정의가 걸린다(위치 이동 경로까지 방어). 엔진은 이 이름들을 쓸 이유가 없다.
RAW_NAMES = {"RawEnvelope", "RawTransaction", "RawMeta", "RawRequest", "RawResponse", "RawParam", "RawHeader", "RawBody"}
# (e) 엔진 검증 파이프라인(②~④). (A) §3.2는 sanitization_check를 명시한다 — 같은 ③ 로직을 담은 형제 모듈
#     (masked_span_check 등)을 우회로로 쓰지 못하게 패키지 전체로 막는다. pipeline 밖 공용 모듈(strict_json·schema·
#     common_types)은 대상이 아니다.
PIPELINE_PACKAGE = "sentinel.pipeline"
# (f) 평가 라벨 경로. 한계(정직 표기): 문자열 상수·이름만 본다 — 런타임 조립('data' + 'sets')·환경 변수·설정 파일로 받는
#     경로는 정적으로 잡지 못한다(engine_tools_isolation과 같은 성격의 한계).
LABEL_PATH_MARKERS = ("datasets", "labels.json")
LABEL_NAMES = {"LabelFile", "Label", "anchor_problems"}
FORBIDDEN_CALLS = {"exec", "eval"}


class BoundaryScanError(RuntimeError):
    """검사 대상이 비었거나 파싱 불가 — 통과로 취급하지 않는다."""


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str  # BURP | SEND | DYNAMIC
    target: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.kind}] {self.target}"


def _under(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _classify(module: str) -> str | None:
    parts = module.lower().split(".")
    if any(p.startswith(BURP_COMPONENTS) for p in parts):
        return BURP
    if any(_under(module, m) for m in SEND_MODULES):
        return SEND
    if _under(module, PIPELINE_PACKAGE):
        return PIPELINE
    if _under(module, TOOLS_PACKAGE):
        return TOOLS
    return None


def _classify_from(module: str, name: str) -> list[str]:
    kinds = [k for k in (_classify(module) or _classify(f"{module}.{name}"),) if k]
    if name in SEND_SYMBOLS.get(module, ()):
        kinds.append(SEND)
    if name in RAW_NAMES:
        kinds.append(RAW)
    if name in LABEL_NAMES and (name != "Label" or "dataset" in module):
        kinds.append(LABELS)
    return kinds


def _dotted(node: ast.Attribute) -> list[str] | None:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    return [cur.id, *reversed(parts)] if isinstance(cur, ast.Name) else None


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.found: list[Violation] = []
        self.module_aliases: dict[str, str] = {}  # 지역 이름 → 모듈 경로(속성 접근 판정용)

    def _add(self, node: ast.AST, kind: str, target: str) -> None:
        self.found.append(Violation(self.path, getattr(node, "lineno", 0), kind, target))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if kind := _classify(alias.name):
                self._add(node, kind, alias.name)
            local = alias.asname or alias.name.split(".")[0]
            self.module_aliases[local] = alias.name if alias.asname else alias.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level > 0:
            for alias in node.names:  # 상대 import도 원본 타입 이름은 잡는다(엔진 안으로 옮겨진 경우)
                if alias.name in RAW_NAMES:
                    self._add(node, RAW, f"{'.' * node.level}{node.module or ''}.{alias.name}")
        if node.level == 0 and node.module:
            for alias in node.names:
                for kind in dict.fromkeys(_classify_from(node.module, alias.name)):
                    self._add(node, kind, f"{node.module}.{alias.name}")
                if alias.name == "*" and node.module in SEND_SYMBOLS:
                    self._add(node, SEND, f"{node.module}.*")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # `import asyncio` 후 `asyncio.open_connection` 같은 송신 심볼 속성 접근
        if isinstance(node.value, ast.Name) and node.value.id in self.module_aliases:
            module = self.module_aliases[node.value.id]
            if node.attr in SEND_SYMBOLS.get(module, ()):
                self._add(node, SEND, f"{module}.{node.attr}")
        if node.attr in RAW_NAMES:  # `import x.raw as r; r.RawTransaction`
            self._add(node, RAW, node.attr)
        if node.attr in LABEL_NAMES and node.attr != "Label":  # `labelfile.LabelFile`
            self._add(node, LABELS, node.attr)
        dotted = _dotted(node)  # `import sentinel` 후 `sentinel.pipeline.sanitization_check` 같은 속성 경로
        if dotted and dotted[0] in self.module_aliases:
            full = ".".join([self.module_aliases[dotted[0]], *dotted[1:]])
            if (kind := _classify(full)) in (PIPELINE, TOOLS):
                self._add(node, kind, full)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and id(node) not in self.docstrings and any(
                m in node.value.lower() for m in LABEL_PATH_MARKERS):
            self._add(node, LABELS, "라벨 경로 문자열")  # 값 자체는 남기지 않는다
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in LABEL_NAMES and node.id != "Label":  # 'Label'은 흔한 이름 — import로만 본다
            self._add(node, LABELS, node.id)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.name in RAW_NAMES:  # 원본 타입 정의 자체가 이 패키지 안에 있음(tools/ 밖으로 옮겨진 경우)
            self._add(node, RAW, f"class {node.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        if name in FORBIDDEN_CALLS:
            self._add(node, DYNAMIC, f"{name}() — 정적 검증 불가")
        elif name in DYNAMIC_IMPORTERS:
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if kind := _classify(arg.value):
                    self._add(node, kind, arg.value)
            else:
                self._add(node, DYNAMIC, f"{name}(<비리터럴>) — 정적 검증 불가")
        self.generic_visit(node)


def scan_source(path: str, source: str) -> list[Violation]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise BoundaryScanError(f"{path}: 파싱 불가 — 검사 통과로 취급하지 않음 ({exc.msg})") from exc
    visitor = _Visitor(path)
    visitor.docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                          if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                          and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    visitor.visit(tree)
    return visitor.found


def scan_package(root: Path) -> list[Violation]:
    files = sorted(root.rglob("*.py")) if root.is_dir() else []
    if not files:
        raise BoundaryScanError(f"{root}: 검사할 .py 파일 없음 — 빈 검사는 통과가 아님")
    found: list[Violation] = []
    for f in files:
        found += scan_source(str(f), f.read_text(encoding="utf-8"))
    return found
