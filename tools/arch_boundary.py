"""아키텍처 경계 정적 검사 — 분석 엔진 패키지의 금지 import 탐지.

(A) §3.2 `engine_burp_isolation`(N4) / §3.1 `no_autonomous_send`(N2, §1.3 ⓐ).
엔진 소스의 AST를 읽어 (a) Burp/Montoya, (b) HTTP 송신·소켓 송신 모듈·심볼의 import를 찾는다.
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


def _classify(module: str) -> str | None:
    parts = module.lower().split(".")
    if any(p.startswith(BURP_COMPONENTS) for p in parts):
        return BURP
    if any(module == m or module.startswith(m + ".") for m in SEND_MODULES):
        return SEND
    return None


def _classify_from(module: str, name: str) -> str | None:
    if kind := _classify(module) or _classify(f"{module}.{name}"):
        return kind
    if name in SEND_SYMBOLS.get(module, ()):
        return SEND
    return None


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
        if node.level == 0 and node.module:
            for alias in node.names:
                if kind := _classify_from(node.module, alias.name):
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
