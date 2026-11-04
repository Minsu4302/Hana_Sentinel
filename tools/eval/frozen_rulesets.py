"""동결된 ruleset 표 — (A) §6.2 (b). `RULESET_VERSION`마다 `rule_engine.py`의 SHA-256을 적는다.

규칙 내용만 바꾸고 버전을 그대로 두면 테스트가 실패한다. 규칙을 바꾸려면 새 버전을 이 표에 더해야 하고, 그것이 동결 행위다.
값이 파일 안에 있을 수 없으므로(자기 해시) 표는 규칙 파일 밖에 둔다.

해시는 줄바꿈을 LF로 정규화해 계산한다 — 체크아웃의 줄바꿈 변환과 무관하게 Git에 저장된 내용의 해시와 같다.
범위: 이 파일 한 개만 본다. 규칙이 쓰는 다른 모듈(`strict_json`·`canonical_address` 등)의 변경은 잡지 못한다.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

FROZEN_RULESETS: Final = {
    "rules-2": "4a4535d623eee4e819842d63523e83a09120da35952635a574d236df6788e62e",
}


def ruleset_file_hash(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
