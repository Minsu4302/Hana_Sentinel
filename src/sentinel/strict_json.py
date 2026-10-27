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


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\n\r":
        i += 1
    return i


def _string_end(s: str, i: int) -> int:
    j = i + 1  # s[i] == '"'
    while s[j] != '"':
        j += 2 if s[j] == "\\" else 1
    return j + 1


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _scan(s: str, i: int, pointer: str, key: str | None, out: list) -> int:
    c = s[i]
    if c == '"':
        end = _string_end(s, i)
        out.append((pointer, key, i, end))
        return end
    if c in "{[":
        close, index = ("}" if c == "{" else "]"), 0
        i = _skip_ws(s, i + 1)
        if s[i] == close:
            return i + 1
        while True:
            if c == "{":
                name_end = _string_end(s, i)
                name = json.loads(s[i:name_end])
                i = _skip_ws(s, _skip_ws(s, name_end) + 1)  # ':' 건너뜀
                i = _scan(s, i, f"{pointer}/{_escape(name)}", name, out)
            else:
                i = _scan(s, i, f"{pointer}/{index}", None, out)
                index += 1
            i = _skip_ws(s, i)
            if s[i] == close:
                return i + 1
            i = _skip_ws(s, i + 1)  # ','
    j = i
    while j < len(s) and s[j] not in ",]} \t\n\r":
        j += 1
    return j


def string_value_spans(content: str) -> list[tuple[str, str | None, int, int]]:
    """문자열 *값* 토큰마다 (JSON Pointer, 멤버 이름 | None, 시작, 끝). 구간은 저장 content의 코드포인트 반열림이며
    따옴표를 포함한다. 객체 멤버 이름은 값이 아니므로 제외. 배열 원소·루트는 멤버 이름 None.
    content는 `parse`를 통과한 엄격 JSON이어야 한다(호출자가 먼저 확인 — 여기서는 문법을 다시 검사하지 않는다)."""
    out: list[tuple[str, str | None, int, int]] = []
    _scan(content, _skip_ws(content, 0), "", None, out)
    return out
