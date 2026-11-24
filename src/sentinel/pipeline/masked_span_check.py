"""파이프라인 ③ 본문 마스킹 표기 검증 — `masked_span_integrity`. (A) §2.2 Body 불변식, §2.3, §2.6 MaskedSpan.

두 가지를 독립으로 제공한다(`sanitization_check`가 둘 다 부른다):
- `check_body_invariants`: 선언된 masked_spans가 Body 불변식 1~7에 맞는지.
    7  절단 표지(§2.6 TRUNCATION_MARK): truncated ⇒ encoding == utf8 ∧ 표지 정확히 1개 / ¬truncated ⇒ 0개 /
       표지는 어떤 FILLER span과도 겹치거나 걸치지 않는다. span 유무와 무관하게 본다.
    1  masked_spans ≠ [] ⇒ encoding == utf8 ∧ content ≠ null
    2  at.kind == text ⇒ range 필수
    2' encoding == omitted ⇒ content == null ∧ masked_spans == [] ∧ truncated == false
    3  span이 가리키는 저장 값 == FILLER(range면 값[start:end] == FILLER ∧ 길이 == len(FILLER),
       json에 range가 없으면 노드 값 자체가 문자열 FILLER)
    4  kind=json은 content 전체가 엄격 JSON으로 파싱될 때만(`sentinel.strict_json`, 잘린 content 불가)
    5  span끼리 겹치지 않음, 같은 노드에 노드 전체 span과 range span 공존 금지 — 같은 kind 안에서만 비교한다
       (text는 content 오프셋, json은 노드 안 오프셋이라 좌표계가 다르다)
    6  정규 순서 (kind, path, start) 오름차순 — 비교는 코드포인트 순서(Java UTF-16 compareTo와의 차이는 Java 연결 시)
  FILLER 비교는 span이 가리킨 위치에서만 한다. 본문 어디에 FILLER 문자열이 있는지 전수 검색하지 않는다 —
  마스킹의 권위는 사이드카다(FILLER를 흉내 낸 본문은 아무것도 증명하지 않는다).
- `rescan_view`: 값 재스캔이 볼 본문. 선언된 span 위치에서 값이 정확히 FILLER일 때만 그 FILLER를 걷어낸다.
  span 위치를 값과 무관하게 건너뛰지 않는다 — 값이 FILLER가 아니면 그대로 남아 재스캔이 본다. 불변식 검사 결과에
  기대지 않는다(두 검사는 함께 성립해야 통과한다).

거부 사유는 `코드@구조 위치`(스키마 필드명·인덱스)만 남긴다. span 내용·JSON 경로·range 값·본문은 남기지 않는다.
"""
from __future__ import annotations

import json
from typing import Any

from sentinel import strict_json
from sentinel.common_types import FILLER, TRUNCATION_MARK
from sentinel.schema import Body


def _span_key(at) -> tuple[str, str, int]:
    """정규 순서 키 (kind, path, start). text는 path 없음(""), 노드 전체 span은 start 없음(-1)."""
    return (at.kind, getattr(at, "path", ""), -1 if at.range is None else at.range.start)


def _is_filler_at(value: Any, rng) -> bool:
    if not isinstance(value, str):
        return False
    if rng is None:
        return value == FILLER
    return rng.end - rng.start == len(FILLER) and value[rng.start:rng.end] == FILLER


def _truncation_mark(body: Body, where: str) -> list[str]:
    """불변식 7: truncated ⇒ utf8이고 표지 정확히 1개 / 아니면 0개 / 표지는 어떤 FILLER span과도 겹치거나 걸치지 않는다."""
    content = body.content if isinstance(body.content, str) else None
    count = content.count(TRUNCATION_MARK) if content is not None else 0
    if not body.truncated:
        return [f"truncation_mark_without_truncated@{where}"] if count else []
    if body.encoding != "utf8" or content is None:
        return [f"truncated_not_utf8@{where}"]
    if count != 1:
        return [f"truncation_mark_count@{where}"]
    start = content.index(TRUNCATION_MARK)
    end = start + len(TRUNCATION_MARK)
    for span in body.masked_spans:
        rng = span.at.range
        if span.at.kind == "text" and rng is not None and rng.start < end and start < rng.end:
            return [f"truncation_mark_overlaps_filler@{where}"]
    return []


def check_body_invariants(body: Body, where: str) -> list[str]:
    spans = body.masked_spans
    if body.encoding == "omitted":  # 불변식 2' — omitted가 우선한다
        found = [f"omitted_with_content@{where}"] if body.content is not None else []
        found += [f"omitted_with_masked_spans@{where}"] if spans else []
        found += [f"omitted_truncated@{where}"] if body.truncated else []
        return found
    marks = _truncation_mark(body, where)  # 불변식 7 — span 유무와 무관
    if not spans:
        return marks
    if body.encoding != "utf8" or body.content is None:  # 불변식 1
        return marks + [f"masked_span_requires_utf8_content@{where}"]

    found: list[str] = list(marks)
    doc: Any = None
    json_ok = False
    if any(s.at.kind == "json" for s in spans):  # 불변식 4
        if not body.truncated:
            try:
                doc, json_ok = strict_json.parse(body.content), True
            except ValueError:
                pass
        if not json_ok:
            found.append(f"masked_span_json_unparseable@{where}")

    for i, span in enumerate(spans):
        at, loc = span.at, f"{where}.masked_spans[{i}]"
        if at.kind == "text":
            if at.range is None:  # 불변식 2
                found.append(f"masked_span_text_without_range@{loc}")
            elif not _is_filler_at(body.content, at.range):  # 불변식 3
                found.append(f"masked_span_not_filler@{loc}")
        elif json_ok:
            ok, node = strict_json.resolve(doc, at.path)
            if not ok:
                found.append(f"masked_span_unresolvable@{loc}")
            elif not _is_filler_at(node, at.range):  # 불변식 3
                found.append(f"masked_span_not_filler@{loc}")

    found += _overlaps(spans, where)  # 불변식 5
    keys = [_span_key(s.at) for s in spans]
    if any(a > b for a, b in zip(keys, keys[1:])):  # 불변식 6(같은 키는 5가 잡는다)
        found.append(f"masked_span_order@{where}")
    return found


def _overlaps(spans, where: str) -> list[str]:
    groups: dict[tuple[str, str], list] = {}
    for span in spans:
        groups.setdefault((span.at.kind, getattr(span.at, "path", "")), []).append(span.at.range)
    for ranges in groups.values():
        if len(ranges) > 1 and None in ranges:  # 노드 전체 span이 다른 span과 같은 노드에
            return [f"masked_span_overlap@{where}"]
        bounded = sorted((r.start, r.end) for r in ranges if r is not None)
        if any(b_start < a_end for (_, a_end), (b_start, _) in zip(bounded, bounded[1:])):
            return [f"masked_span_overlap@{where}"]
    return []


def _strippable(value: Any) -> bool:
    return value == FILLER  # 값이 정확히 FILLER일 때만 걷어낸다(위치 건너뛰기 아님)


def rescan_segments(body: Body) -> str | list[str] | None:
    """값 재스캔이 볼 본문((A) §2.3). 절단된 본문은 불변식 7이 성립할 때만(표지 정확히 1개, FILLER span과 비겹침)
    원본 content를 표지 앞·뒤 두 구간으로 나누고, 각 구간에서 선언된 FILLER만 걷어낸다. 표지를 가로지르는 매칭은 원본에 없는
    텍스트에 대한 매칭이라 판정 근거가 아니다. 불변식 7을 어기면 나누지 않는다(전체를 본다 — 거부는 불변식 7이 한다).
    나누기를 먼저 하고 걷어내기를 나중에 한다: 걷어낸 뒤 나누면 FILLER 양옆 조각이 이어져 새 표지가 생길 수 있다."""
    if not body.truncated or _truncation_mark(body, "rescan"):
        return rescan_view(body)
    content = body.content
    start = content.index(TRUNCATION_MARK)
    end = start + len(TRUNCATION_MARK)
    head, tail = content[:start], content[end:]
    cuts = sorted({(s.at.range.start, s.at.range.end) for s in body.masked_spans
                   if s.at.kind == "text" and s.at.range is not None
                   and _strippable(content[s.at.range.start:s.at.range.end])}, reverse=True)
    for lo, hi in cuts:  # 불변식 7이 비겹침을 보장 — 각 FILLER는 한 구간 안에 있다
        if hi <= start:
            head = head[:lo] + head[hi:]
        elif lo >= end:
            tail = tail[:lo - end] + tail[hi - end:]
    return [head, tail]


def rescan_view(body: Body) -> str | None:
    """값 재스캔용 본문: 선언된 span 위치의 FILLER만 걷어낸 content. 그 밖의 경우 content 그대로."""
    content = body.content  # 재스캔 대상 원문
    if not body.masked_spans or body.encoding != "utf8" or content is None:
        return content
    json_ats = [s.at for s in body.masked_spans if s.at.kind == "json"]
    if json_ats and not body.truncated:
        try:
            doc = strict_json.parse(content)
        except ValueError:
            doc = None
        if doc is not None:
            # JSON 노드의 원문 오프셋은 알 수 없으므로 파싱한 문서에서 걷어내고 다시 직렬화한다.
            # text span의 FILLER는 이 경로에서 걷어내지 않는다(두 kind를 섞은 본문은 fail-closed — 거부될 수 있음).
            return json.dumps(_strip_json(doc, json_ats), ensure_ascii=False)
    cuts = sorted({(s.at.range.start, s.at.range.end) for s in body.masked_spans
                   if s.at.kind == "text" and s.at.range is not None
                   and _strippable(content[s.at.range.start:s.at.range.end])}, reverse=True)
    for start, end in cuts:
        content = content[:start] + content[end:]
    return content


def _strip_json(doc: Any, ats) -> Any:
    holder = [doc]  # 루트 노드도 같은 방식으로 바꾸기 위한 상자
    targets: dict[tuple[int, Any], list] = {}
    for at in ats:
        ok, parent, key = strict_json.locate(holder[0], at.path)
        if not ok:
            continue
        container, slot = (holder, 0) if parent is None else (parent, key)
        targets.setdefault((id(container), slot), [container, slot, set()])[2].add(
            None if at.range is None else (at.range.start, at.range.end))
    for container, slot, ranges in targets.values():
        value = container[slot]
        if None in ranges:
            if _strippable(value):
                container[slot] = ""
            continue
        if not isinstance(value, str):
            continue
        for start, end in sorted(ranges, reverse=True):
            if _strippable(value[start:end]):
                value = value[:start] + value[end:]
        container[slot] = value
    return holder[0]
