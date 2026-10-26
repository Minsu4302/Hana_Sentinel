"""엄격 JSON·JSON Pointer 해석 — (A) §2.6 BodyPointer의 단일 정의. 출력 게이트·③·fixture 마스커가 같이 쓴다.

'content 전체가 JSON으로 파싱됨' = RFC 8259 엄격 파싱: NaN·Infinity, 후행 문자열, 중복 키를 허용하지 않는다
(중복 키는 '경로가 노드 정확히 1개'를 깨뜨린다). JSON Pointer(RFC 6901) 문법 검사는 타입(`common_types`)이 하고,
여기서는 문서에서의 해석만 한다 — 배열 인덱스의 선행 0은 배열을 만났을 때 거부한다.

순수 함수만 둔다(입출력·로깅 없음). `sentinel.pipeline` 밖에 두는 이유: 마스커가 `sanitization_check`를
import하지 않고도 같은 정의를 쓸 수 있어야 한다(`masker_independence`).
"""
from __future__ import annotations

import json
import re
from typing import Any, Final

_ARRAY_INDEX: Final = re.compile(r"^(0|[1-9][0-9]*)$")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("중복 키 — 경로가 노드 1개를 가리키지 못함")
    return dict(pairs)


def _no_constant(_: str) -> Any:
    raise ValueError("NaN·Infinity는 표준 JSON이 아님")


def parse(content: str) -> Any:
    """엄격 파싱. 실패하면 ValueError(메시지에 값 없음)."""
    return json.loads(content, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)


def locate(doc: Any, pointer: str) -> tuple[bool, Any, Any]:
    """(found, 부모 컨테이너, 키/인덱스). 루트("")는 부모 None. 해석 실패면 (False, None, None)."""
    parent, key, node = None, None, doc
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            parent, key, node = node, token, node[token]
        elif isinstance(node, list) and _ARRAY_INDEX.match(token) and int(token) < len(node):
            parent, key, node = node, int(token), node[int(token)]
        else:
            return False, None, None
    return True, parent, key


def resolve(doc: Any, pointer: str) -> tuple[bool, Any]:
    """(found, 노드). 해석 실패면 (False, None)."""
    found, parent, key = locate(doc, pointer)
    if not found:
        return False, None
    return True, (doc if parent is None else parent[key])
