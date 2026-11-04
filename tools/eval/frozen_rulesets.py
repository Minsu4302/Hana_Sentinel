"""동결 표 — (A) §6.2. ruleset(§6.2 (b))은 `RULESET_VERSION`마다 규칙 파일 3개(`RULESET_FILES`)의 묶음 해시를, 라벨링 지침은
버전마다 `docs/labeling-guideline.md`의 SHA-256을 적는다.

규칙 내용만 바꾸고 버전을 그대로 두면 테스트가 실패한다. 규칙을 바꾸려면 새 버전을 이 표에 더해야 하고, 그것이 동결 행위다.
값이 파일 안에 있을 수 없으므로(자기 해시) 표는 규칙 파일 밖에 둔다.

해시는 줄바꿈을 LF로 정규화해 계산한다 — 체크아웃의 줄바꿈 변환과 무관하게 Git에 저장된 내용의 해시와 같다.
범위: 타입 파일(common_types·output_schema·schema)은 제외한다 — LLM 결선이 바꾸는 계약 파일이라 넣으면 규칙이 그대로여도 동결이
깨진다. 타입 변경은 잡지 못한다(한계).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

import sentinel

RULESET_FILES: Final = ("pipeline/rule_engine.py", "strict_json.py", "canonical_address.py")  # sentinel 패키지 기준
FROZEN_RULESETS: Final = {
    "rules-2": "ef8d3ce2deb941bde40c6fd69836578926a0d52410bfa8f08e107fb4404fde2f",
}
# 같은 버전의 범위 확장 기록: 규칙 내용은 그대로이고 해시 범위만 넓어졌다. 값 = 확장 전 rule_engine.py 단독 해시.
RULESET_SCOPE_HISTORY: Final = {
    "rules-2": "4a4535d623eee4e819842d63523e83a09120da35952635a574d236df6788e62e",
}
FROZEN_GUIDELINES: Final = {
    "v1": "abd4c6896a179f209466b35fd1b55406dec91bd8788d7948bffa00093846aae7",
}


def frozen_file_hash(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def current_ruleset_hash(package_root: Path | None = None) -> str:
    root = Path(sentinel.__file__).parent if package_root is None else Path(package_root)
    digest = hashlib.sha256()
    for rel in RULESET_FILES:
        digest.update(f"{rel}\0{frozen_file_hash(root / rel)}\n".encode("utf-8"))
    return digest.hexdigest()


def guideline_is_frozen(path: Path, version: str) -> bool:
    return frozen_file_hash(path) == FROZEN_GUIDELINES.get(version)
