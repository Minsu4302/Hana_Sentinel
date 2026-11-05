"""어댑터 정적 검사 — (A) §3.1 `llm_adapter_loopback_only`·`llm_adapter_no_target_resend`.

`loopback_violations`: 연결 생성자 1개, 인자 고정(상수 127.0.0.1, 포트 이름, timeout만) / HTTPSConnection·set_tunnel·source_address·
.host·.port 대입·host= 키워드·상속·별칭 import·getattr 금지 / 요청 메서드·경로는 상수 / 메시지 content는 입력의 문자열 필드만 /
어댑터 API 인자에 대상 요청을 다시 만들 이름이 없음.
`adapter_call_sites`: src/sentinel에서 어댑터를 부르는 곳. 지금은 0곳이다(결선 전 — 결선 PR에서 재증명).

범위(정직 표기): 정적 범위다. 런타임 조립은 금지 이름 검사로만 막는다. 포트에서 듣는 프로세스의 정체는 범위 밖이다
(`inference_server_binding`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

ADAPTER_REL: Final = "pipeline/llm_adapter.py"
LOOPBACK: Final = "127.0.0.1"
FORBIDDEN_NAMES: Final = frozenset({"HTTPSConnection", "set_tunnel", "source_address", "_tunnel", "_tunnel_host", "_tunnel_port"})
FORBIDDEN_CALLS: Final = frozenset({"getattr", "setattr", "delattr", "vars", "eval", "exec", "compile", "__import__"})
FORBIDDEN_KEYWORDS: Final = frozenset({"host", "source_address", "blocksize"})
FORBIDDEN_PARAMS: Final = frozenset({"host", "hostname", "url", "uri", "method", "path", "target", "address"})
FORBIDDEN_STORES: Final = frozenset({"host", "port", "sock"})


def _imports(tree: ast.AST) -> list[str]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"aliased_import:{a.name}" for a in node.names if a.name == "http.client" and a.asname]
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "http":
            found.append("from_http_import")
    return found


def _names(tree: ast.AST) -> list[str]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_NAMES:
            found.append(f"forbidden:{node.attr}")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            found.append(f"forbidden:{node.id}")
        if isinstance(node, ast.Constant) and node.value in FORBIDDEN_NAMES:
            found.append(f"forbidden:{node.value}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            found.append(f"forbidden_call:{node.func.id}")
        if isinstance(node, ast.keyword) and node.arg in FORBIDDEN_KEYWORDS:
            found.append(f"forbidden_keyword:{node.arg}")
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store) and node.attr in FORBIDDEN_STORES:
            found.append(f"forbidden_store:{node.attr}")
        if isinstance(node, ast.ClassDef) and any("http" in ast.dump(base) or "HTTP" in ast.dump(base) for base in node.bases):
            found.append("subclass_of_http_client")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            found += [f"forbidden_param:{a.arg}" for a in args if a.arg in FORBIDDEN_PARAMS]
    return found


def _is_connection(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "HTTPConnection"


def _constructor(tree: ast.AST) -> list[str]:
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_connection(n.func)]
    funcs = {id(n.func) for n in calls}
    annotations = {id(sub) for n in ast.walk(tree) if isinstance(n, ast.arg) and n.annotation is not None
                   for sub in ast.walk(n.annotation)}
    bare = [n for n in ast.walk(tree) if _is_connection(n) and id(n) not in funcs and id(n) not in annotations]
    found = ["connection_reference"] * len(bare)
    if len(calls) != 1:
        return [*found, f"constructor_count={len(calls)}"]
    call = calls[0]
    first_ok = len(call.args) == 2 and isinstance(call.args[0], ast.Constant) and call.args[0].value == LOOPBACK
    if not first_ok:
        found.append("constructor_arguments")
    if {k.arg for k in call.keywords} - {"timeout"}:
        found.append("constructor_keywords")
    return found


def _request(tree: ast.AST) -> list[str]:
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "request"]
    if len(calls) != 1:
        return [f"request_count={len(calls)}"]
    args = calls[0].args
    ok = (len(args) == 2 and isinstance(args[0], ast.Name) and args[0].id == "COMPLETIONS_METHOD"
          and isinstance(args[1], ast.Name) and args[1].id == "COMPLETIONS_PATH")
    return [] if ok else ["request_not_constant"]


def _content(tree: ast.AST) -> list[str]:
    values = [v for n in ast.walk(tree) if isinstance(n, ast.Dict) for k, v in zip(n.keys, n.values)
              if isinstance(k, ast.Constant) and k.value == "content"]
    if len(values) != 1:
        return [f"content_count={len(values)}"]
    value = values[0]
    return [] if isinstance(value, ast.Attribute) and value.attr == "content" else ["content_not_the_input_string"]


def loopback_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)


def adapter_call_sites(package_root: Path) -> list[str]:
    root = Path(package_root)
    found = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel == ADAPTER_REL:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or "", *(a.name for a in node.names)]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any("llm_adapter" in name for name in names):
                found.append(f"{rel}:{node.lineno}")
    return found
