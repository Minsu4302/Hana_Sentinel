"""영구 제외 '부재' 정적 검사 — (A) §1.3 ⓓ 자동 반영 / ⓔ 파인튜닝 / ⓕ 원본 저장.

엔진 패키지(`src/sentinel`)의 AST에서 각 영구 제외 기능을 *구현할 수 있는 수단*(모듈 import·호출·정의된
심볼 이름)을 찾는다. 기능이 '없다'는 것은 직접 증명할 수 없으므로, 그 기능에 필요한 통로가 코드에 없음을
보이는 방식이다. 허용 예외는 ALLOWED에 파일 단위로만 둔다(현재: 감사 저장소의 sqlite3 하나).
검사 대상이 비었거나 파싱 불가하면 '위반 없음'이 아니라 오류(fail-closed).

한계(정직 표기): 목록 기반 정적 검사다 — 목록 밖 라이브러리, 런타임 조립 문자열·getattr 우회, 제3자 패키지
내부 동작은 잡지 못한다. 원본 저장(ⓕ)은 런타임 관측 테스트(tests/test_absence.py)로 한 겹 더 확인한다.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

AUTOPATCH = "no_autopatch_apply"
FINETUNE = "no_finetune_path"
RAW_PERSIST = "no_raw_persistence"

# ⓓ 자동 반영: 프로세스 실행(외부 git/patch 호출), VCS 조작, 패치 적용 라이브러리
AUTOPATCH_MODULES = ("subprocess", "pty", "git", "pygit2", "dulwich", "unidiff", "whatthepatch", "patch", "patch_ng",
                     "multiprocessing")
AUTOPATCH_CALLS = {"system", "popen", "spawnl", "spawnv", "spawnve", "execv", "execve", "execl", "execvp",
                   "startfile", "posix_spawn"}  # os.* 프로세스 실행
AUTOPATCH_NAME = re.compile(r"(?i)(auto_?patch|apply_?(patch|fix|diff|remediation|suggestion)|patch_?apply|"
                            r"self_?modif|auto_?fix|auto_?remediat|commit_?fix)")

# ⓔ 파인튜닝: 학습 프레임워크 + Trainer류 심볼
FINETUNE_MODULES = ("peft", "trl", "accelerate", "deepspeed", "unsloth", "axolotl", "torchtune", "bitsandbytes")
FINETUNE_SYMBOLS = {"Trainer", "TrainingArguments", "Seq2SeqTrainer", "Seq2SeqTrainingArguments", "SFTTrainer",
                    "DPOTrainer", "LoraConfig", "get_peft_model"}
# 이름은 식별자 단위로 검사하므로 밑줄을 경계로 본다(\b는 밑줄을 단어 문자로 취급해 build_lora_x를 놓침)
FINETUNE_NAME = re.compile(r"(?i)(fine_?tun|trainer|training_?(data|set|args)|(^|_)(lora|qlora|sft|dpo|rlhf|peft)(_|$))")

# ⓕ 원본 저장: 임시파일·직렬화 저장·파일 로그 핸들러·DB, 파일 쓰기 호출, 표준출력 덤프
RAW_PERSIST_MODULES = ("tempfile", "pickle", "shelve", "dbm", "marshal", "sqlite3", "logging.handlers", "mmap",
                       "zipfile", "tarfile", "gzip", "bz2", "lzma", "csv")
RAW_WRITE_ATTRS = {"write_text", "write_bytes", "write", "writelines", "dump", "touch", "FileHandler",
                   "RotatingFileHandler", "TimedRotatingFileHandler", "WatchedFileHandler"}
RAW_WRITE_CALLS = {"print", "open"}  # 이름 호출(builtins)·os.open/io.open 등 속성 호출 둘 다
_WRITE_MODE = re.compile(r"[wax+]")

# 파일 단위 허용(경로는 패키지 루트 기준). 감사 저장소는 위생 처리된 메시지만 쓴다(W1-07·런타임 관측 테스트).
ALLOWED: dict[str, set[str]] = {
    "audit.py": {"module:sqlite3"},
}


class AbsenceScanError(RuntimeError):
    """검사 대상이 비었거나 파싱 불가 — 통과로 취급하지 않는다."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    key: str  # 위반한 manifest 키
    what: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.key}] {self.what}"


def _module_hits(module: str) -> list[tuple[str, str]]:
    hits = []
    for key, mods in ((AUTOPATCH, AUTOPATCH_MODULES), (FINETUNE, FINETUNE_MODULES), (RAW_PERSIST, RAW_PERSIST_MODULES)):
        if any(module == m or module.startswith(m + ".") for m in mods):
            hits.append((key, f"module:{module.split('.')[0] if key != RAW_PERSIST else module}"))
    return hits


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.found: list[Finding] = []

    def _add(self, node: ast.AST, key: str, what: str) -> None:
        self.found.append(Finding(self.rel, getattr(node, "lineno", 0), key, what))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            for key, what in _module_hits(alias.name):
                self._add(node, key, what)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:
            for key, what in _module_hits(node.module):
                self._add(node, key, what)
            for alias in node.names:
                for key, what in _module_hits(f"{node.module}.{alias.name}"):
                    self._add(node, key, what)
                if alias.name in FINETUNE_SYMBOLS:
                    self._add(node, FINETUNE, f"symbol:{alias.name}")
                if alias.name in RAW_WRITE_ATTRS:
                    self._add(node, RAW_PERSIST, f"symbol:{alias.name}")
                if node.module == "os" and alias.name in AUTOPATCH_CALLS:
                    self._add(node, AUTOPATCH, f"symbol:os.{alias.name}")
        self.generic_visit(node)

    def _check_name(self, node: ast.AST, name: str) -> None:
        if AUTOPATCH_NAME.search(name):
            self._add(node, AUTOPATCH, f"name:{name}")
        if FINETUNE_NAME.search(name):
            self._add(node, FINETUNE, f"name:{name}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_name(node, node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._check_name(node, node.name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in FINETUNE_SYMBOLS:
            self._add(node, FINETUNE, f"symbol:{node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if name in RAW_WRITE_CALLS:
                if name == "print" or self._open_may_write(node):
                    self._add(node, RAW_PERSIST, f"call:{name}")
            self._check_name(node, name)
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in RAW_WRITE_ATTRS:
                self._add(node, RAW_PERSIST, f"call:.{attr}")
            if attr == "open" and self._open_may_write(node, attr_call=True):
                self._add(node, RAW_PERSIST, "call:.open")
            if isinstance(func.value, ast.Name) and func.value.id == "os" and attr in AUTOPATCH_CALLS | {"write"}:
                self._add(node, AUTOPATCH if attr in AUTOPATCH_CALLS else RAW_PERSIST, f"call:os.{attr}")
            self._check_name(node, attr)
        self.generic_visit(node)

    @staticmethod
    def _open_may_write(node: ast.Call, attr_call: bool = False) -> bool:
        """open의 모드가 쓰기일 수 있으면 True. 모드가 리터럴 읽기 전용임이 확실할 때만 False(fail-closed)."""
        mode_arg = None
        index = 0 if attr_call else 1  # Path.open(mode) vs open(file, mode)
        if len(node.args) > index:
            mode_arg = node.args[index]
        for kw in node.keywords:
            if kw.arg in ("mode", "flags"):
                mode_arg = kw.value
        if mode_arg is None:
            return False  # 기본 "r"
        if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
            return bool(_WRITE_MODE.search(mode_arg.value))
        return True  # 비리터럴·정수 플래그 → 쓰기 가능으로 간주


def scan_source(rel: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        raise AbsenceScanError(f"{rel}: 파싱 불가 — 통과로 취급하지 않음 ({exc.msg})") from exc
    visitor = _Visitor(rel)
    visitor.visit(tree)
    allowed = ALLOWED.get(rel, set())
    return [f for f in visitor.found if f.what not in allowed]


def scan_package(root: Path) -> list[Finding]:
    files = sorted(root.rglob("*.py")) if root.is_dir() else []
    if not files:
        raise AbsenceScanError(f"{root}: 검사할 .py 파일 없음 — 빈 검사는 통과가 아님")
    found: list[Finding] = []
    for f in files:
        found += scan_source(f.relative_to(root).as_posix(), f.read_text(encoding="utf-8"))
    return found
