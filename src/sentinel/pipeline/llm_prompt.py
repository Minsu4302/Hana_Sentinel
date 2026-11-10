"""LLM 입력의 모양 — (A) §2.8. 프롬프트 템플릿, 입력 뷰, 전송 스키마, 묶음 해시. 송신은 없다.

- 프롬프트: `prompts/analysis.txt`. 고정 지시문(system)과 구획된 데이터 블록(user)을 `---USER---`로 가른다.
- 입력 뷰: 순서는 헤더 → 파라미터 → 본문이고 본문은 머리와 꼬리를 보존한다. §2.2의 절단과는 별개다. 뷰에는 host·scheme·port가 없다.
  `>`를 JSON 이스케이프하므로 데이터 안의 문자열이 닫는 표지를 만들지 못한다.
- 전송 스키마: 정의처는 Pydantic FindingDraft 목록이다. `$ref`를 풀어 평탄화하고 Locator의 range를 뺀다(뷰 오프셋 ≠ 원본 오프셋).
  초안 형태를 맞추려고 `advisory_signals`는 빈 배열로 고정한다 — LLM은 advisory를 만들지 않는다.
- 출력 규칙 절: 전송 스키마로 표현하지 않는(또는 서버가 강제하지 못하는) 초안 계약의 하위 제약을 `OUTPUT_RULES`에서 기계적으로
  펼친다(`llm_contract_conveyed`). 절 밖의 지시문은 템플릿 파일 그대로다. 전달만 보장한다 — 모델이 지키는지는 게이트가 판정한다.
- `prompt_version`: 템플릿 + 생성 설정의 묶음 해시. 측정 뒤 설정만 바꿔도 같은 버전으로 기록되는 구멍을 막는다.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel.output_schema import AnalysisDraft

TEMPLATE_PATH: Final = Path(__file__).parent / "prompts" / "analysis.txt"
RULES_SLOT: Final = "{output_rules}"
RULES_HEADING: Final = "Output rules:"
# 하위 제약·게이트 검사 ID → 출력 규칙 문장. ID는 tools/eval/schema_gap의 분해 표·게이트 검사 표와 같다(고정 테스트가 맞춘다)
OUTPUT_RULES: Final[dict[str, tuple[str, ...]]] = {
    "gate.locus_names": ("resp_status = status, req_line = method or path, req_header = req_headers, resp_header = resp_headers, "
                         "req_param = params.",),
    "gate.occurrence": ("occurrence counts from 0: for headers, among headers with the same name ignoring case; "
                        "for params, among params with the same location and name.",),
    "gate.body_kind": ("Use body kind json only when the body content is JSON and truncated is false; otherwise use kind text.",),
    "json_pointer.one_node": ("A body path is a JSON Pointer: nested keys as /a/b, array items as /a/0. "
                              "Never write nesting with dots or brackets (not a.b, not a[0]).",
                              "Use only body paths that actually exist in the DATA block."),
    "json_pointer.no_dash_token": ("A body path never uses - as a whole segment (not /items/-).",),
}


def _with_rules(raw: str) -> str:
    if raw.count(RULES_SLOT) != 1 or raw.count(RULES_HEADING) != 1:
        raise ValueError("출력 규칙 자리와 제목은 템플릿에 정확히 하나씩")
    return raw.replace(RULES_SLOT, "\n".join(f"- {line}" for lines in OUTPUT_RULES.values() for line in lines))


TEMPLATE_TEXT: Final = _with_rules(TEMPLATE_PATH.read_bytes().replace(b"\r\n", b"\n").decode("utf-8"))
SYSTEM_PROMPT, USER_TEMPLATE = (part.strip() for part in TEMPLATE_TEXT.split("---USER---"))
VIEW_SLOT: Final = "{view}"
CUT_MARK: Final = "…[view cut]…"
SCHEMA_NOISE: Final = frozenset({"title", "description", "discriminator", "$defs"})
LLM_DROPPED_FIELDS: Final = frozenset({"range"})


# ── 전송 스키마 ────────────────────────────────────────────────────

def _inlined(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, list):
        return [_inlined(item, defs) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        return _inlined(defs[node["$ref"].rsplit("/", 1)[-1]], defs)
    flat = {key: _inlined(value, defs) for key, value in node.items() if key not in SCHEMA_NOISE and key != "properties"}
    if "properties" in node:
        flat["properties"] = {name: _inlined(value, defs) for name, value in node["properties"].items() if name not in LLM_DROPPED_FIELDS}
    if "required" in flat:
        flat["required"] = [name for name in flat["required"] if name not in LLM_DROPPED_FIELDS]
    return flat


def transmission_schema() -> dict[str, Any]:
    schema = AnalysisDraft.model_json_schema()
    flat = _inlined(schema, schema.get("$defs", {}))
    flat["properties"]["advisory_signals"] = {"type": "array", "maxItems": 0}
    return flat


TRANSMISSION_SCHEMA: Final = transmission_schema()


# ── 묶음 해시 ──────────────────────────────────────────────────────

def prompt_version(*, temperature: float, max_tokens: int, view_bytes: int, deadline_seconds: float,
                   template: str = TEMPLATE_TEXT, schema: dict[str, Any] = TRANSMISSION_SCHEMA) -> str:
    bundle = {"template_sha256": hashlib.sha256(template.encode("utf-8")).hexdigest(), "temperature": float(temperature),
              "max_tokens": max_tokens, "view_bytes": view_bytes, "deadline_seconds": float(deadline_seconds), "schema": schema}
    return hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# ── 입력 뷰 ────────────────────────────────────────────────────────

def _encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace(">", "\\u003e")


def _size(value: Any) -> int:
    return len(_encoded(value).encode("utf-8"))


def _head_and_tail(text: str, budget: int) -> str:
    """text의 머리와 꼬리를 남겨 인코딩 크기가 budget 안에 들게 한다. 들어갈 자리가 없으면 빈 문자열."""
    def cut(keep: int) -> str:
        return text[:keep] + CUT_MARK + text[len(text) - keep:]

    low, high = 0, len(text) // 2
    if _size(cut(low)) > budget:
        return ""
    while low < high:
        middle = (low + high + 1) // 2
        low, high = (middle, high) if _size(cut(middle)) <= budget else (low, middle - 1)
    return cut(low)


def _body_view(body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """content를 뺀 뼈대와, 뷰에 못 담는 내용인지 여부. omitted는 원래 없는 것이라 뷰가 잘린 것이 아니다."""
    shown = {"content_type": body["content_type"], "encoding": body["encoding"], "truncated": body["truncated"]}
    return shown, body["encoding"] == "base64"


def _skeleton(tx: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    request, response = tx["request"], tx["response"]
    req_body, req_hidden = _body_view(request["body"])
    resp_body, resp_hidden = _body_view(response["body"])
    view = {"transaction_id": tx["meta"]["transaction_id"], "method": request["method"], "path": request["path"],
            "status": response["status"], "req_headers": request["headers"], "resp_headers": response["headers"],
            "params": request["query_params"], "req_body": req_body, "resp_body": resp_body}
    return view, req_hidden or resp_hidden


def _shrunk(view: dict[str, Any], budget: int) -> bool:
    """뼈대가 예산을 넘으면 뒤부터 뺀다: 파라미터 → 응답 헤더 → 요청 헤더 → 경로의 가운데."""
    cut = False
    for field in ("params", "resp_headers", "req_headers"):
        while view[field] and _size(view) > budget:
            view[field].pop()
            cut = True
    if _size(view) > budget:
        view["path"] = _head_and_tail(view["path"], max(0, budget - _size({**view, "path": ""})))
        cut = True
    return cut


def _with_bodies(view: dict[str, Any], tx: dict[str, Any], budget: int) -> bool:
    """남은 예산을 두 본문에 나눈다. 한쪽이 덜 쓰면 다른 쪽이 쓴다."""
    bodies = [(key, side["body"]["content"]) for key, side in (("req_body", tx["request"]), ("resp_body", tx["response"]))
              if side["body"]["encoding"] == "utf8" and side["body"]["content"]]
    cut = False
    for index, (key, text) in enumerate(bodies):
        room = max(0, budget - _size(view) - len('"content":"",'))
        share = room // (len(bodies) - index)
        whole = _size(text)
        kept = text if whole <= share else _head_and_tail(text, share)
        cut = cut or kept != text
        if kept:  # 자리가 없으면 키도 넣지 않는다 — 빈 키가 예산을 넘겨 트랜잭션째 빠지면 안 된다
            view[key]["content"] = kept
    return cut


def _tx_view(tx: dict[str, Any], budget: int) -> tuple[dict[str, Any], bool]:
    view, hidden = _skeleton(tx)
    shrunk = _shrunk(view, budget)
    return view, _with_bodies(view, tx, budget) or hidden or shrunk


def render_view(transactions_json: str, limit: int) -> tuple[str, bool]:
    """③ 스냅샷 → (뷰 문자열, 잘렸는가). 인코딩 크기는 항상 limit 이하다."""
    transactions = json.loads(transactions_json)["transactions"]
    overhead = _size({"transactions": [None] * len(transactions)})
    budget = max(0, limit - overhead) // max(1, len(transactions))
    parts = [_tx_view(tx, budget) for tx in transactions]
    views = [view for view, _cut in parts]
    truncated = any(cut for _view, cut in parts)
    while views and _size({"transactions": views}) > limit:
        views.pop()
        truncated = True
    return _encoded({"transactions": views}), truncated


def user_message(view: str) -> str:
    return USER_TEMPLATE.replace(VIEW_SLOT, view)
