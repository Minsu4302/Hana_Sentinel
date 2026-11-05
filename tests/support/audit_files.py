"""감사 저장소의 파일 전체 바이트 — 값 미기록 검사가 읽는 대상. 본 파일과 곁 파일(`-journal`·`-wal`·`-shm`)을 모두 읽는다.

SQLite는 커밋 때 곁 파일을 지운다. Windows에서는 삭제가 끝나기 전까지 파일이 목록에 남고, 그 사이 읽으면 FileNotFoundError나
PermissionError가 난다. 사라진 곁 파일에는 읽을 내용이 없으므로 그것만 견딘다. 범위를 줄이지 않는다:
- 본 파일과 곁 파일이 아닌 파일은 못 읽으면 실패한다.
- 곁 파일이 잠긴 채 남아 있으면 재시도 뒤 실패한다(읽지 못한 내용을 깨끗하다고 하지 않는다).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Final

SIDECAR_SUFFIXES: Final = ("-journal", "-wal", "-shm")
ATTEMPTS: Final = 100
WAIT_SECONDS: Final = 0.01


def _sidecar_bytes(path: Path) -> bytes:
    for attempt in range(ATTEMPTS):
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return b""
        except PermissionError:
            if attempt == ATTEMPTS - 1:
                raise
            time.sleep(WAIT_SECONDS)
    raise AssertionError("도달하지 않는다")


def audit_store_bytes(store: Path) -> bytes:
    chunks = [store.read_bytes()]
    for path in sorted(store.parent.iterdir()):
        if path == store or not path.name.startswith(store.name):
            continue
        sidecar = path.name[len(store.name):] in SIDECAR_SUFFIXES
        chunks.append(_sidecar_bytes(path) if sidecar else path.read_bytes())
    return b"".join(chunks)
