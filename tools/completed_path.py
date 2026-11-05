"""생성 지점 정적 검사 — (A) §3.5 `completed_via_gate`, §3.1 `llm_input_from_sanitized`. src/sentinel에서 아래 타입이 만들어지는 곳은
각각 한 곳뿐.

- AnalysisResult: `pipeline/output_gate.py`의 `_assign` 안 생성자 호출 1개
- ExecutionResponse: `pipeline/execution.py`의 `build_execution_response` 안 생성자 호출 1개
- SanitizedEnvelope: `pipeline/sanitization_check.py`의 `verify_sanitization` 안 생성자 호출 1개
- LlmInput: `pipeline/llm_adapter.py`의 `llm_input` 안 생성자 호출 1개(그곳의 `isinstance` 입력 확인 1개는 허용)

금지(범위는 src/sentinel — tools·tests 제외):
  ① 두 이름의 그 밖의 값 참조 전부: 다른 곳의 생성자, `.model_validate*`, `TypeAdapter(...)`, 별칭 대입, 상속, 문자열 표기.
     타입 표기(인자·반환·필드 주석)와 별칭 없는 import는 값 참조가 아니라 허용한다.
  ② 받는 쪽을 가리지 않는 우회 생성: `model_construct`·`construct`·`parse_obj`·`parse_raw`·`parse_file`·`from_orm`.
  ③ 게이트 건너뛰기: `_build` 참조는 `validate_producers` 안에서만, `_assign` 참조는 `_build` 안에서만(검사 ①~⑤ 없이 AnalysisResult에
     닿는 함수들).
  ④ 저장 필드 직접 쓰기: `__setattr__`·`__delattr__`·`__dict__` 참조(문자열 표기 포함)와 `vars(...)` — frozen을 우회하는 경로.
     읽기도 함께 막는다(src/sentinel에 쓸 일이 없고, 읽기와 쓰기를 정적으로 가르면 구멍이 남는다).
  ⑤ 인스턴스에서 새 값을 찍는 경로: `.model_copy(...)`(헤더 이름 정규화 `_normalized` 한 곳만 예외 — 대상이 Locator),
     `.copy(...)`, `.__class__`, `type(x)(...)`. `copy.deepcopy`는 값을 바꿀 인자가 없어 대상이 아니다.

범위(정직 표기): 정적 범위다. getattr·import 런타임 조립은 여기서 잡지 않는다(그 경로는 `DYNAMIC` 금지 종류의 몫).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

BUILDERS: Final = {"AnalysisResult": ("pipeline/output_gate.py", "_assign"),
                   "ExecutionResponse": ("pipeline/execution.py", "build_execution_response"),
                   "SanitizedEnvelope": ("pipeline/sanitization_check.py", "verify_sanitization"),
                   "LlmInput": ("pipeline/llm_adapter.py", "llm_input")}
ISINSTANCE_SITES: Final = {"SanitizedEnvelope": ("pipeline/llm_adapter.py", "llm_input")}  # 입력 타입 확인 1곳
BYPASS_ATTRS: Final = frozenset({"model_construct", "construct", "parse_obj", "parse_raw", "parse_file", "from_orm"})
MODEL_COPY_SITE: Final = ("pipeline/output_gate.py", "_normalized")
RAW_WRITE_NAMES: Final = frozenset({"__setattr__", "__delattr__", "__dict__"})
GATE_INTERNALS: Final = {"_assign": ("pipeline/output_gate.py", "_build"),
                         "_build": ("pipeline/output_gate.py", "validate_producers")}


class _Scan(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.function = ""
        self.violations: list[str] = []
        self.builds: dict[str, int] = dict.fromkeys(BUILDERS, 0)

    def _flag(self, code: str, node: ast.AST) -> None:
        self.violations.append(f"{code}@{self.rel}:{node.lineno}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        outer, self.function = self.function, node.name
        for child in [*node.args.defaults, *node.args.kw_defaults, *node.decorator_list, *node.body]:
            if child is not None:
                self.visit(child)
        self.function = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "dataclasses" and any(a.name == "replace" for a in node.names):
            self._flag("bypass:replace", node)
        for alias in node.names:
            if alias.name in BUILDERS and alias.asname:
                self._flag(f"aliased_import:{alias.name}", node)

    def _allowed_isinstance(self, node: ast.Call) -> bool:
        return (isinstance(node.func, ast.Name) and node.func.id == "isinstance" and len(node.args) == 2
                and isinstance(node.args[1], ast.Name)
                and ISINSTANCE_SITES.get(node.args[1].id) == (self.rel, self.function))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if self._allowed_isinstance(node):
            self.visit(node.args[0])
            return
        if isinstance(func, ast.Name) and BUILDERS.get(func.id) == (self.rel, self.function):
            self.builds[func.id] += 1
            for child in [*node.args, *node.keywords]:
                self.visit(child)
            return
        if isinstance(func, ast.Attribute):
            if func.attr == "model_copy" and (self.rel, self.function) != MODEL_COPY_SITE:
                self._flag("model_copy", node)
            if func.attr == "copy":
                self._flag("copy", node)
        if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "type":
            self._flag("type_call", node)
        self.generic_visit(node)

    def _check_assign(self, name: str, node: ast.AST) -> None:
        if name in GATE_INTERNALS and (self.rel, self.function) != GATE_INTERNALS[name]:
            self._flag("gate_skipped", node)

    def visit_Name(self, node: ast.Name) -> None:
        self._check_assign(node.id, node)
        if node.id == "vars":
            self._flag("raw_write:vars", node)
        if node.id in BUILDERS:
            self._flag(f"reference:{node.id}", node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_assign(node.attr, node)
        if node.attr == "replace" and isinstance(node.value, ast.Name) and node.value.id == "dataclasses":
            self._flag("bypass:replace", node)
        if node.attr in BUILDERS:
            self._flag(f"reference:{node.attr}", node)
        if node.attr in BYPASS_ATTRS or node.attr == "__class__":
            self._flag(f"bypass:{node.attr}", node)
        if node.attr in RAW_WRITE_NAMES:
            self._flag(f"raw_write:{node.attr}", node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if node.value in BUILDERS or node.value in RAW_WRITE_NAMES:
            self._flag(f"string:{node.value}", node)


def construction_violations(root: Path) -> list[str]:
    """root = src/sentinel에 해당하는 패키지 디렉터리. 위반(사유 코드@상대경로:줄)."""
    root = Path(root)
    found: list[str] = []
    builds = dict.fromkeys(BUILDERS, 0)
    for path in sorted(root.rglob("*.py")):
        scan = _Scan(path.relative_to(root).as_posix())
        scan.visit(ast.parse(path.read_text(encoding="utf-8")))
        found += scan.violations
        for name, count in scan.builds.items():
            builds[name] += count
    found += [f"build_count:{name}={count}" for name, count in sorted(builds.items()) if count != 1]
    return found
