"""변이 적용 유효성 장치 — 변이 확인이 '거짓 통과'하지 않게 한다(W1-08 교훈, W1-09 `manifest_selfcheck`).

W1-08에서 변이 확인 하나가 거짓 통과했다: 고친 모듈과 pytest가 실제로 부른 모듈이 달라 변이가 적용되지
않았는데, 결과만 보고 '확인됨'으로 읽을 뻔했다. 변이 결과를 읽기 전에 다음 두 가지를 먼저 증명한다.

1. 치환이 실제로 일어났다 — 대상 문자열이 정확히 1회 있어야 하고, 결과가 원문과 달라야 한다.
2. 실행 중 로드된 모듈이 변이본이다 — 실행 출력의 활성 표지(`<stamp> module=<경로>`)가 가리키는 파일이
   변이본 경로와 같아야 한다. 표지가 없으면(플러그인 미로드) 그 실행은 아무것도 증명하지 않는다.

둘 중 하나라도 어긋나면 MutationNotApplied — 결과를 해석하지 않고 그 자체를 실패로 본다.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


class MutationNotApplied(AssertionError):
    """변이가 적용되지 않았거나 실행이 변이본을 쓰지 않았다 — 결과를 해석하지 않는다."""


def apply_mutation(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise MutationNotApplied(f"변이 대상이 정확히 1회가 아님({count}회): {old!r}")
    mutated = source.replace(old, new)
    if mutated == source:
        raise MutationNotApplied(f"치환 결과가 원문과 같음: {old!r}")
    return mutated


def copy_with_mutation(src_root: Path, packages: list[str], dest_root: Path, rel_file: str,
                       old: str, new: str) -> Path:
    """src_root의 패키지들을 dest_root로 복사하고 rel_file 하나에 변이를 적용한다. 변이본 경로를 돌려준다."""
    for pkg in packages:
        src = src_root / pkg
        if src.is_dir():
            shutil.copytree(src, dest_root / pkg, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
        else:
            (dest_root / pkg).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest_root / pkg)
    target = dest_root / rel_file
    target.write_text(apply_mutation(target.read_text(encoding="utf-8"), old, new), encoding="utf-8")
    return target.resolve()


def loaded_from(output: str, stamp: str) -> list[Path]:
    """실행 출력에서 활성 표지가 가리키는 모듈 경로들."""
    return [Path(m) for m in re.findall(re.escape(stamp) + r" module=(.+?) keys=", output)]


def _same(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve()))


def assert_loaded_from(output: str, stamp: str, expected: Path) -> None:
    paths = loaded_from(output, stamp)
    if not paths:
        raise MutationNotApplied(f"활성 표지 {stamp!r} 없음 — 검사 대상 모듈이 로드되지 않음")
    wrong = [p for p in paths if not _same(p, expected)]
    if wrong:
        raise MutationNotApplied(f"실행 중 로드된 모듈 {wrong[0]} ≠ 기대 {expected} — 다른 사본이 실행됨")
