"""CNA 정규화 함수 — `canonical_address`. (A) §2.6 CNA·정규화 규칙, §2.4 중복 처리, §6.1 판정 단위.

핵심: 같은 값을 가리키는 서로 다른 Locator가 같은 CNA로 정규화된다(각 승격 규칙). 승격에 실패하면 거친 노드
(body_text)로 떨어진다. 다른 값은 다른 CNA다. 모드와 무관하게 항상 적용된다(마스킹 모드는 Locator·CNA에 없다).
함수 위치는 엔진 안(pipeline 밖) — 마스커·평가기가 tools → 엔진 방향으로 써도 `masker_independence` 위반이 아니다.
변이 확인은 변이본 로드 표지를 먼저 확인한다. 테스트 transaction은 Juice Shop 형태의 더미(N5).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from sentinel.canonical_address import CNA, canonical_address
from sentinel.common_types import Locator
from sentinel.schema import Transaction
from tools.arch_boundary import PIPELINE, scan_source
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
REF = uuid.UUID("00000000-0000-4000-8000-0000000000c3")
LOC = TypeAdapter(Locator)

REQ_JSON = '{"user": {"email": "dummy@juice-sh.op", "tags": ["a", "b😀"]}, "note": "😀😀ab"}'
FORM = "email=dummy%40juice-sh.op&pw=s3cret&pw=again&remember=on"


def _body(content, ctype="application/json", truncated=False) -> dict:
    return {"content_type": ctype, "size_bytes": len(content.encode()), "truncated": truncated, "encoding": "utf8",
            "content": content}


def _tx(req_body=None, resp_body=None, ref: uuid.UUID = REF) -> Transaction:
    doc = {"meta": {"transaction_id": str(ref), "captured_at": "2026-10-27T10:00:00+09:00", "origin_ref": "burp-1",
                    "sanitization": {"applied": True, "failed": False, "policy_version": "p1", "redacted_count": 0,
                                     "redacted_kinds": {"token": 0, "cookie": 0, "pii": 0, "host": 0}}},
           "request": {"method": "POST", "scheme": "http", "host": "127.0.0.1", "port": 3000, "path": "/rest/user/login",
                       "query_params": [{"name": "q", "value": "apple", "location": "query"}],
                       "headers": [{"name": "X-Trace", "value": "a"}, {"name": "x-trace", "value": "b"}],
                       "body": req_body or _body(REQ_JSON)},
           "response": {"status": 200, "headers": [], "body": resp_body or _body('{"msg": "hello world"}'),
                        "elapsed_ms": 1}}
    return Transaction.model_validate_json(json.dumps(doc, ensure_ascii=False))


def _cna(tx: Transaction, locator: dict) -> CNA:
    return canonical_address(tx, LOC.validate_python(locator))


def _range_of(content: str, needle: str, inner: tuple[int, int] = (0, 0)) -> dict:
    start = content.index(needle) + inner[0]
    return {"start": start, "end": start + len(needle) - inner[0] - inner[1]}


# ── 같은 값 → 같은 CNA(승격 규칙마다) ──────────────────────────────────────

def test_text_range_inside_json_string_promotes_to_the_json_node():
    tx = _tx()
    by_path = _cna(tx, {"locus": "req_body", "body": {"kind": "json", "path": "/user/email"}})
    by_text = _cna(tx, {"locus": "req_body", "body": {"kind": "text", "range": _range_of(REQ_JSON, "juice-sh")}})
    by_path_with_range = _cna(tx, {"locus": "req_body", "body": {"kind": "json", "path": "/user/email",
                                                                 "range": {"start": 0, "end": 5}}})
    assert by_path == by_text == by_path_with_range == CNA(REF, ("body_json", "req", "/user/email"))


def test_text_range_inside_nested_array_string_and_emoji_offsets():
    tx = _tx()
    expected = CNA(REF, ("body_json", "req", "/user/tags/1"))
    assert _cna(tx, {"locus": "req_body", "body": {"kind": "text", "range": _range_of(REQ_JSON, '"b😀"', (1, 1))}}) == expected
    assert _cna(tx, {"locus": "req_body", "body": {"kind": "json", "path": "/user/tags/1"}}) == expected


def test_text_range_inside_form_value_promotes_to_the_form_param():
    tx = _tx(req_body=_body(FORM, "application/x-www-form-urlencoded; charset=utf-8"))
    by_param = _cna(tx, {"locus": "req_param", "location": "form", "name": "pw", "occurrence": 1})
    by_text = _cna(tx, {"locus": "req_body", "body": {"kind": "text", "range": _range_of(FORM, "again")}})
    by_param_range = _cna(tx, {"locus": "req_param", "location": "form", "name": "pw", "occurrence": 1,
                               "range": {"start": 0, "end": 2}})
    assert by_param == by_text == by_param_range == CNA(REF, ("param", "form", "pw", 1))
    # 인코딩된 이름·값: 이름은 디코드해 Param.name 기준, 오프셋은 저장 content 기준
    assert _cna(tx, {"locus": "req_body", "body": {"kind": "text", "range": _range_of(FORM, "dummy%40")}}) == \
        CNA(REF, ("param", "form", "email", 0))


def test_header_range_and_name_case_are_dropped():
    tx = _tx()
    plain = _cna(tx, {"locus": "req_header", "name": "x-trace", "occurrence": 1})
    ranged = _cna(tx, {"locus": "req_header", "name": "X-TRACE", "occurrence": 1, "range": {"start": 0, "end": 1}})
    assert plain == ranged == CNA(REF, ("header", "req", "x-trace", 1))


def test_req_line_path_range_is_dropped():
    tx = _tx()
    assert _cna(tx, {"locus": "req_line", "part": "path", "range": {"start": 1, "end": 5}}) == \
        _cna(tx, {"locus": "req_line", "part": "path"}) == CNA(REF, ("req_line.path",))


def test_response_side_json_promotion_and_status():
    tx = _tx()
    content = '{"msg": "hello world"}'
    assert _cna(tx, {"locus": "resp_body", "body": {"kind": "text", "range": _range_of(content, "world")}}) == \
        _cna(tx, {"locus": "resp_body", "body": {"kind": "json", "path": "/msg"}}) == CNA(REF, ("body_json", "resp", "/msg"))
    assert _cna(tx, {"locus": "resp_status"}) == CNA(REF, ("resp_status",))


# ── 승격 실패 → 거친 노드(body_text) ─────────────────────────────────────

@pytest.mark.parametrize("case", ["range_across_two_form_values", "range_over_json_key", "range_includes_quote",
                                  "truncated_json", "no_range", "response_form_body", "non_json_text"])
def test_failed_promotion_falls_back_to_body_text(case):
    if case == "range_across_two_form_values":
        tx, side, rng = _tx(req_body=_body(FORM, "application/x-www-form-urlencoded")), "req", _range_of(FORM, "s3cret&pw")
    elif case == "range_over_json_key":
        tx, side, rng = _tx(), "req", _range_of(REQ_JSON, "email", (0, 0))
    elif case == "range_includes_quote":
        tx, side, rng = _tx(), "req", _range_of(REQ_JSON, '"dummy')
    elif case == "truncated_json":
        tx, side, rng = _tx(req_body=_body(REQ_JSON, truncated=True)), "req", _range_of(REQ_JSON, "juice-sh")
    elif case == "no_range":
        tx, side, rng = _tx(), "req", None
    elif case == "response_form_body":
        tx, side, rng = _tx(resp_body=_body(FORM, "application/x-www-form-urlencoded")), "resp", _range_of(FORM, "again")
    else:
        tx, side, rng = _tx(req_body=_body("plain text body", "text/plain")), "req", {"start": 0, "end": 5}
    body = {"kind": "text"} if rng is None else {"kind": "text", "range": rng}
    assert _cna(tx, {"locus": f"{side}_body", "body": body}) == CNA(REF, ("body_text", side))


# ── 다른 값 → 다른 CNA ────────────────────────────────────────────────

def test_different_nodes_or_transactions_get_different_cnas():
    tx, other = _tx(), _tx(ref=uuid.uuid4())
    cnas = {
        _cna(tx, {"locus": "req_header", "name": "x-trace", "occurrence": 0}),
        _cna(tx, {"locus": "req_header", "name": "x-trace", "occurrence": 1}),
        _cna(tx, {"locus": "resp_header", "name": "x-trace", "occurrence": 0}),
        _cna(tx, {"locus": "req_param", "location": "query", "name": "q"}),
        _cna(tx, {"locus": "req_param", "location": "form", "name": "q"}),
        _cna(tx, {"locus": "req_body", "body": {"kind": "json", "path": "/user/email"}}),
        _cna(tx, {"locus": "req_body", "body": {"kind": "json", "path": "/note"}}),
        _cna(tx, {"locus": "req_line", "part": "method"}),
        _cna(other, {"locus": "req_line", "part": "method"}),
    }
    assert len(cnas) == 9


def test_function_lives_outside_the_pipeline_so_masker_may_import_it():
    assert scan_source("m.py", "from sentinel.canonical_address import canonical_address\n") == []
    assert not (REPO_ROOT / "src" / "sentinel" / "pipeline" / "canonical_address.py").exists()
    assert {v.kind for v in scan_source("m.py", "from sentinel.pipeline.canonical_address import x\n")} == {PIPELINE}


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "canonical_address_probe"
_DRIVER = """
import sys, pytest
import sentinel.canonical_address  # pytest의 pythonpath 삽입 전에 변이본을 먼저 적재
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_canonical_address.py::"
MUTATIONS = {
    "form_promotion_off": ("            if _inside(rng, start, end):\n                return (\"param\", \"form\", name, occurrence)\n",
                           "            pass\n", [_T + "test_text_range_inside_form_value_promotes_to_the_form_param"]),
    "json_promotion_off": ("            if _inside(rng, start + 1, end - 1):  # 따옴표 안\n", "            if False:\n",
                           [_T + "test_text_range_inside_json_string_promotes_to_the_json_node",
                            _T + "test_response_side_json_promotion_and_status"]),
    "json_promotion_includes_quotes": ("            if _inside(rng, start + 1, end - 1):  # 따옴표 안\n",
                                       "            if _inside(rng, start, end):\n",
                                       [_T + "test_failed_promotion_falls_back_to_body_text"]),
    "header_case_kept": ('"resp", locator.name.lower(), locator.occurrence)', '"resp", locator.name, locator.occurrence)',
                         [_T + "test_header_range_and_name_case_are_dropped"]),
    "header_range_kept": ('"resp", locator.name.lower(), locator.occurrence)',
                          '"resp", locator.name.lower(), locator.occurrence, locator.range)',
                          [_T + "test_header_range_and_name_case_are_dropped"]),
    "req_line_range_kept": ('        node: tuple = (f"req_line.{locator.part}",)\n',
                            '        node = (f"req_line.{locator.part}", locator.range)\n',
                            [_T + "test_req_line_path_range_is_dropped"]),
    "param_range_kept": ("        node = (\"param\", locator.location, locator.name, locator.occurrence)\n",
                         "        node = (\"param\", locator.location, locator.name, locator.occurrence, locator.range)\n",
                         [_T + "test_text_range_inside_form_value_promotes_to_the_form_param"]),
    "json_path_range_kept": ('            node = ("body_json", side, locator.body.path)\n',
                             '            node = ("body_json", side, locator.body.path, locator.body.range)\n',
                             [_T + "test_text_range_inside_json_string_promotes_to_the_json_node"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_normalization_rule_is_load_bearing_under_verified_mutation(tmp_path, name):
    old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], tmp_path / "mut" / "src",
                                "sentinel/canonical_address.py", old, new)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut" / "src"), str(REPO_ROOT)]),
           "PYTHONUTF8": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), "sentinel.canonical_address", *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
