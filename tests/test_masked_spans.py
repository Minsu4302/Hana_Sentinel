"""본문 마스킹 표기 — `masked_span_integrity`. (A) §2.2 Body 불변식 1~6, §2.3 값 재스캔, §2.6 MaskedRef·FILLER·MaskedSpan.

'위조 거부'로 증명한다: 불변식 1~6 각각의 위반, FILLER 아닌 값을 가리키는 span, 선언 없는 FILLER 흉내, 형식 밖 라벨이
모두 거부된다. 대조: 패턴에 걸리는 이름(password·token·session)을 정확히 마스킹한 본문은 ③을 통과한다 — 안전한
이름(email 등)으로만 만든 대조는 '문제를 가린 통과'라 쓰지 않는다.

두 검사의 독립성: 불변식 검사(선언된 span이 규칙에 맞음)와 값 재스캔(span 위치의 FILLER만 걷어낸 본문에 생문자열
없음)은 서로의 결과에 기대지 않는다. 한쪽만 걸리는 입력을 각각 두고, 한쪽을 끈 변이가 다른 쪽 테스트를 통과시키지
않음을 보인다(변이본 로드 표지를 먼저 확인). 가짜 비밀값은 런타임 조립(N5·N7).
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

import sentinel.schema
from sentinel.common_types import FILLER, MaskedRef
from sentinel.pipeline.sanitization_check import SanitizationRejected, verify_sanitization
from sentinel.pipeline.schema_gate import SchemaRejected, parse_envelope
from tests.test_schema import T0, _env, _raw
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PW, TK = "pass" + "word", "to" + "ken"  # 패턴 이름 — 리터럴 조립(시크릿 스캔 오탐 방지)
SECRET = "hun" + "ter2x"  # FILLER와 같은 8자 — 길이만으로는 구별되지 않는 생문자열
assert len(SECRET) == len(FILLER)  # 9자면 span을 통째 걷어내도 1자가 남아 '건너뛰기' 변이가 살아남는다(실제로 겪음)


def _ref(label: str | None = "ref_01", kind: str = "token") -> dict:
    return {"masked": True, "label": label, "kind": kind}


def _text(start: int, end: int | None = None, **ref) -> dict:
    return {"at": {"kind": "text", "range": {"start": start, "end": start + len(FILLER) if end is None else end}},
            "ref": _ref(**ref)}


def _json(path: str, start: int | None = None, end: int | None = None, **ref) -> dict:
    at: dict = {"kind": "json", "path": path}
    if start is not None:
        at["range"] = {"start": start, "end": start + len(FILLER) if end is None else end}
    return {"at": at, "ref": _ref(**ref)}


def _with_body(content, spans, *, side="request", encoding="utf8", truncated=False, ctype="text/plain") -> dict:
    env = _env()
    env["transactions"][0][side]["body"] = {
        "content_type": ctype, "size_bytes": len((content or "").encode()), "truncated": truncated,
        "encoding": encoding, "content": content, "masked_spans": spans}
    return env


def _passes(env: dict) -> None:
    verify_sanitization(parse_envelope(_raw(env)))


def _codes(env: dict) -> set[str]:
    with pytest.raises(SanitizationRejected) as exc:
        verify_sanitization(parse_envelope(_raw(env)))
    return {r.split("@")[0] for r in exc.value.reasons}


# ── FILLER·MaskedRef 단일 정의 ─────────────────────────────────────

def test_filler_constant_equals_the_canonical_value_in_A():
    text = (REPO_ROOT / "docs" / "design-decision.md").read_text(encoding="utf-8")
    values = re.findall(r'^FILLER\s+=\s+"([^"]*)"', text, flags=re.M)
    assert values == [FILLER] == ["[MASKED]"]


def test_filler_and_masked_ref_are_defined_only_in_common_types():
    src = REPO_ROOT / "src" / "sentinel"
    for path in src.rglob("*.py"):
        if path.name == "common_types.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert '"[MASKED]"' not in text and "'[MASKED]'" not in text, path
        assert not re.search(r"^\s*(FILLER\s*[:=]|class MaskedRef\b|class MaskedSpan\b)", text, flags=re.M), path
    assert sentinel.schema.MaskedRef is MaskedRef  # schema는 재정의하지 않고 가져다 쓴다


def _sentinel_imports(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] == "sentinel"]
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "sentinel":
            found.append(node.module)
    return found


@pytest.mark.parametrize("module", ["common_types.py", "strict_json.py"])
def test_shared_definition_modules_import_nothing_else_from_sentinel(module):
    """의존 방향 common_types·strict_json → 나머지 한쪽뿐((A) §2.6). 역방향 import가 생기면 실패."""
    assert _sentinel_imports(REPO_ROOT / "src" / "sentinel" / module) == []


def test_import_checker_detects_a_sentinel_import_as_control(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text("from sentinel.schema import Body\nimport sentinel.pipeline\nimport json\n", encoding="utf-8")
    assert _sentinel_imports(probe) == ["sentinel.schema", "sentinel.pipeline"]


# ── 위조 거부: 라벨 형식(② 타입) ────────────────────────────────────

@pytest.mark.parametrize("label", ["ref_1", "ref_abc", "principal_01", "session_01", "REF_01", "ref_01234", "ref_01\n",
                                   "ref-01", ""])
def test_rejects_label_outside_ref_nn_in_span_ref(label):
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_with_body(f"a={FILLER}", [_text(2, label=label)])))


@pytest.mark.parametrize("span", [
    {"at": {"kind": "text", "range": {"start": 0, "end": 8}}, "ref": _ref(), "value": "x"},
    {"at": {"kind": "text", "range": {"start": 0, "end": 8}}, "ref": {**_ref(), "original": "x"}},
    {"at": {"kind": "xml", "range": {"start": 0, "end": 8}}, "ref": _ref()},
    {"at": {"kind": "json", "path": "/a/-"}, "ref": _ref()},
    {"at": {"kind": "text", "range": {"start": 0, "end": 8}}},
])
def test_rejects_malformed_masked_span(span):
    with pytest.raises(SchemaRejected):
        parse_envelope(_raw(_with_body(FILLER, [span])))


@pytest.mark.parametrize("label", ["ref_01", "ref_9999", None])
def test_ref_nn_label_and_null_are_accepted(label):
    _passes(_with_body(f"a={FILLER}", [_text(2, label=label)]))


# ── 대조: 패턴에 걸리는 이름을 정확히 마스킹한 본문은 통과 ─────────────────────

CLEAN = {
    "json_password_node": (json.dumps({PW: FILLER, "user": "alice"}), [_json(f"/{PW}")], "application/json"),
    "json_token_node": (json.dumps({TK: FILLER}), [_json(f"/{TK}")], "application/json"),
    "json_range_in_string": (json.dumps({"q": f"session={FILLER}&x=1"}), [_json("/q", 8)], "application/json"),
    "form_password": (f"user=alice&{PW}={FILLER}&x=1", [_text(20)], "application/x-www-form-urlencoded"),
    "cookie_session": (f"session={FILLER}; theme=dark", [_text(8)], "text/plain"),
    "two_text_spans_in_order": (f"{TK}={FILLER}&{PW}={FILLER}", [_text(6), _text(24)], "text/plain"),
    "json_two_nodes_in_order": (json.dumps({"a": FILLER, "b": {TK: FILLER}}), [_json("/a"), _json(f"/b/{TK}")],
                                "application/json"),
    "whole_content_is_filler": (FILLER, [_text(0)], "text/plain"),
    "json_root_string": (json.dumps(FILLER), [_json("")], "application/json"),
}


@pytest.mark.parametrize("name", sorted(CLEAN))
@pytest.mark.parametrize("side", ["request", "response"])
def test_correctly_masked_body_with_credential_names_passes(name, side):
    content, spans, ctype = CLEAN[name]
    _passes(_with_body(content, spans, side=side, ctype=ctype))


def test_same_label_in_header_and_body_span_is_not_rejected():
    """라벨 일관성은 생산자 몫(`label_consistency`, ζ2b 비강제) — 같은 라벨이 거부되지 않음만 확인."""
    env = _with_body(f"{PW}={FILLER}", [_text(9, label="ref_01", kind="cookie")])
    env["transactions"][0]["request"]["headers"] = [{"name": "Cookie", "value": _ref("ref_01", "cookie")}]
    _passes(env)


def test_masked_body_without_spans_still_passes_when_clean():
    _passes(_with_body("plain text body", []))


# ── 위조 거부: 불변식 1~6 ─────────────────────────────────────────

INVARIANT_VIOLATIONS = {
    # 1: span ⇒ utf8 ∧ content ≠ null
    "inv1_base64": (dict(content="W01BU0tFRF0=", spans=[_text(0)], encoding="base64"),
                    {"masked_span_requires_utf8_content"}),
    "inv1_utf8_null_content": (dict(content=None, spans=[_text(0)]), {"masked_span_requires_utf8_content"}),
    # 2: text ⇒ range
    "inv2_text_without_range": (dict(content=FILLER, spans=[{"at": {"kind": "text"}, "ref": _ref()}]),
                                {"masked_span_text_without_range"}),
    # 2': omitted ⇒ content null ∧ spans [] ∧ not truncated
    "inv2p_omitted_with_spans": (dict(content=None, spans=[_text(0)], encoding="omitted"),
                                 {"omitted_with_masked_spans"}),
    "inv2p_omitted_truncated": (dict(content=None, spans=[], encoding="omitted", truncated=True),
                                {"omitted_truncated"}),
    "inv2p_omitted_with_content": (dict(content="x", spans=[], encoding="omitted"), {"omitted_with_content"}),
    # 3: 가리킨 값 == FILLER
    "inv3_text_not_filler": (dict(content="a=harmless", spans=[_text(2)]), {"masked_span_not_filler"}),
    "inv3_range_shorter_than_filler": (dict(content=f"a={FILLER}", spans=[_text(2, 9)]), {"masked_span_not_filler"}),
    "inv3_range_longer_than_filler": (dict(content=f"a={FILLER}x", spans=[_text(2, 11)]), {"masked_span_not_filler"}),
    "inv3_range_beyond_content": (dict(content=f"a={FILLER[:-1]}", spans=[_text(2)]), {"masked_span_not_filler"}),
    "inv3_json_node_not_filler": (dict(content='{"a": "harmless"}', spans=[_json("/a")]), {"masked_span_not_filler"}),
    "inv3_json_node_not_string": (dict(content='{"a": 12345678}', spans=[_json("/a")]), {"masked_span_not_filler"}),
    "inv3_json_range_on_object": (dict(content='{"a": {"b": 1}}', spans=[_json("/a", 0)]), {"masked_span_not_filler"}),
    "inv3_json_path_missing": (dict(content=json.dumps({"a": FILLER}), spans=[_json("/b")]),
                               {"masked_span_unresolvable"}),
    # 4: json ⇒ content 전체가 엄격 JSON
    "inv4_not_json": (dict(content=f"x {FILLER}", spans=[_json("")]), {"masked_span_json_unparseable"}),
    "inv4_truncated": (dict(content=json.dumps({"a": FILLER}), spans=[_json("/a")], truncated=True),
                       {"masked_span_json_unparseable"}),
    "inv4_duplicate_key": (dict(content=f'{{"a": "{FILLER}", "a": "{FILLER}"}}', spans=[_json("/a")]),
                           {"masked_span_json_unparseable"}),
    "inv4_nan": (dict(content=f'{{"a": "{FILLER}", "b": NaN}}', spans=[_json("/a")]),
                 {"masked_span_json_unparseable"}),
    "inv4_trailing": (dict(content=f'{{"a": "{FILLER}"}} x', spans=[_json("/a")]), {"masked_span_json_unparseable"}),
    # 5: 같은 kind 안에서 겹침 금지 / 노드 전체 span + range span 공존 금지
    "inv5_duplicate_text_range": (dict(content=f"a={FILLER}", spans=[_text(2), _text(2)]), {"masked_span_overlap"}),
    "inv5_partial_text_overlap": (dict(content=f"{FILLER}{FILLER}", spans=[_text(0), _text(4)]),
                                  {"masked_span_overlap", "masked_span_not_filler"}),
    "inv5_node_and_range_same_node": (dict(content=json.dumps({"a": FILLER}), spans=[_json("/a"), _json("/a", 0)]),
                                      {"masked_span_overlap"}),
    "inv5_duplicate_node_span": (dict(content=json.dumps({"a": FILLER}), spans=[_json("/a"), _json("/a")]),
                                 {"masked_span_overlap"}),
    # 6: 정규 순서 (kind, path, start)
    "inv6_text_start_descending": (dict(content=f"{FILLER}&{FILLER}", spans=[_text(9), _text(0)]),
                                   {"masked_span_order"}),
    "inv6_json_path_descending": (dict(content=json.dumps({"a": FILLER, "b": FILLER}), spans=[_json("/b"), _json("/a")]),
                                  {"masked_span_order"}),
}


@pytest.mark.parametrize("name", sorted(INVARIANT_VIOLATIONS))
def test_rejects_body_invariant_violation(name):
    kwargs, expected = INVARIANT_VIOLATIONS[name]
    assert _codes(_with_body(kwargs.pop("content"), kwargs.pop("spans"), **kwargs)) == expected


def test_kind_order_json_before_text():
    """6: kind가 정렬 키의 첫 자리 — text 다음 json은 순서 위반. (서로 다른 kind의 겹침은 비교하지 않는다 — 5 한정)"""
    content = json.dumps({"a": FILLER})
    assert "masked_span_order" in _codes(_with_body(content, [_text(7), _json("/a")]))


# ── 위치 한정: FILLER 비교는 span이 가리킨 위치에서만 ───────────────────────

def test_filler_elsewhere_does_not_vouch_for_a_span_on_another_value():
    """FILLER 흉내: 본문 다른 곳에 FILLER가 있어도, span이 가리킨 값이 FILLER가 아니면 거부."""
    assert _codes(_with_body(f"{FILLER} a=harmless", [_text(11)])) == {"masked_span_not_filler"}


# ── 두 검사의 독립성 ───────────────────────────────────────────────

def test_span_on_non_filler_harmless_value_is_caught_by_integrity_only():
    """재스캔은 이 입력에서 아무것도 못 본다 — 불변식 3만 거부한다(integrity가 하중을 진다)."""
    assert _codes(_with_body("note=harmless&x=1", [_text(5)])) == {"masked_span_not_filler"}


def test_span_declared_on_a_raw_secret_is_caught_by_both_checks():
    """공격자가 비밀 위치를 span으로 선언: 불변식 3이 거부하고, 값이 FILLER가 아니라 걷어내지 않으므로 재스캔도 본다."""
    codes = _codes(_with_body(f"user=alice&{PW}={SECRET}&x=1", [_text(20)]))
    assert codes == {"masked_span_not_filler", "credential_form_field"}


def test_undeclared_filler_under_credential_name_is_still_rescanned():
    """면제는 선언된 span 위치에 한정: 선언 안 된 `password=[MASKED]`는 걷어내지 않으므로 재스캔이 거부한다."""
    content = f"{TK}={FILLER}&{PW}={FILLER}"
    assert _codes(_with_body(content, [_text(6)])) == {"credential_form_field"}


def test_raw_secret_outside_valid_spans_is_caught_by_rescan_only():
    content = f"{TK}={FILLER}&{PW}={SECRET}"
    assert _codes(_with_body(content, [_text(6)])) == {"credential_form_field"}


def test_secret_glued_to_a_declared_filler_is_rescanned():
    """걷어낸 뒤 남는 것은 그대로 재스캔: `password=[MASKED]secret`은 FILLER를 걷어내도 `password=secret`."""
    assert _codes(_with_body(f"{PW}={FILLER}{SECRET}", [_text(9)])) == {"credential_form_field"}


def test_json_secret_outside_span_is_rescanned():
    content = json.dumps({PW: FILLER, "x": {TK: SECRET}})
    assert _codes(_with_body(content, [_json(f"/{PW}")], ctype="application/json")) == {"credential_json_field"}


def test_mixed_kind_body_is_fail_closed_documented_limitation():
    """정직한 한계: json span이 있는 본문은 문서를 다시 직렬화해 재스캔하므로 text span의 FILLER는 걷어내지 않는다.
    그래서 두 kind를 섞어 자격증명 이름을 가리면 거부될 수 있다(과잉 거부 방향 — 비밀이 새는 방향이 아님)."""
    content = json.dumps({"a": FILLER, "q": f"x&{PW}={FILLER}"})
    spans = [_json("/a"), _text(content.index(f"{PW}=") + len(PW) + 1)]
    assert _codes(_with_body(content, spans, ctype="application/json")) == {"credential_form_field"}


# ── 감사 위생: 사유 코드·구조 위치만 ──────────────────────────────────

def test_span_rejection_audit_has_no_path_range_or_content_values(caplog):
    key, value = "k" + secrets.token_hex(6), "v" + secrets.token_hex(6)
    content = json.dumps({key: value})
    with caplog.at_level(logging.WARNING, logger="sentinel.audit"):
        codes = _codes(_with_body(content, [_json(f"/{key}", 1, 9)], ctype="application/json"))
    assert codes == {"masked_span_not_filler"}
    dump = " ".join(r.getMessage() + repr(r.__dict__) for r in caplog.records if r.name == "sentinel.audit")
    assert "masked_span_not_filler@tx0.request.body.masked_spans[0]" in dump
    assert key not in dump and value not in dump and "start" not in dump


# ── 변이 확인: 각 검사가 하중을 지지한다(변이본 로드 먼저 증명) ───────────────────

STAMP = "masked_span_probe"
_DRIVER = """
import sys, pytest
import sentinel.pipeline.masked_span_check, sentinel.pipeline.sanitization_check  # pytest보다 먼저 변이본 적재
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_masked_spans.py::"
_MSC = ("sentinel/pipeline/masked_span_check.py", "sentinel.pipeline.masked_span_check")
_SC = ("sentinel/pipeline/sanitization_check.py", "sentinel.pipeline.sanitization_check")
_INV = _T + "test_rejects_body_invariant_violation"
MUTATIONS = {
    "inv1_off": (*_MSC, '    if body.encoding != "utf8" or body.content is None:  # 불변식 1\n', "    if False:\n",
                 [_INV + "[inv1_base64]"]),
    "inv2_off": (*_MSC, "            if at.range is None:  # 불변식 2\n", "            if False:\n",
                 [_INV + "[inv2_text_without_range]"]),
    "inv2p_off": (*_MSC, '    if body.encoding == "omitted":  # 불변식 2\'', "    if False:  #",
                  [_INV + "[inv2p_omitted_with_spans]", _INV + "[inv2p_omitted_truncated]",
                   _INV + "[inv2p_omitted_with_content]",
                   "tests/test_sanitization.py::test_omitted_body_with_content_is_rejected"]),
    "inv3_off": (*_MSC, "def _is_filler_at(value: Any, rng) -> bool:\n",
                 "def _is_filler_at(value: Any, rng) -> bool:\n    return True\n",
                 [_INV + "[inv3_text_not_filler]", _INV + "[inv3_json_node_not_filler]",
                  _INV + "[inv3_range_shorter_than_filler]",
                  _T + "test_span_on_non_filler_harmless_value_is_caught_by_integrity_only"]),
    "inv3_global_filler_search": (*_MSC, "            elif not _is_filler_at(body.content, at.range):  # 불변식 3\n",
                                  "            elif FILLER not in body.content:\n",
                                  [_T + "test_filler_elsewhere_does_not_vouch_for_a_span_on_another_value"]),
    "inv4_off": (*_MSC, '        if not json_ok:\n            found.append(f"masked_span_json_unparseable@{where}")\n',
                 "        if False:\n            pass\n",
                 [_INV + "[inv4_not_json]", _INV + "[inv4_truncated]", _INV + "[inv4_duplicate_key]"]),
    "inv5_off": (*_MSC, "    found += _overlaps(spans, where)  # 불변식 5\n", "    found += []\n",
                 [_INV + "[inv5_node_and_range_same_node]", _INV + "[inv5_duplicate_text_range]"]),
    "inv6_off": (*_MSC, "    if any(a > b for a, b in zip(keys, keys[1:])):", "    if False:",
                 [_INV + "[inv6_text_start_descending]", _INV + "[inv6_json_path_descending]"]),
    # 재스캔: span 위치를 값과 무관하게 통째 건너뛰기 → span에 선언된 생문자열이 재스캔을 피한다
    "rescan_skips_span_regardless_of_value": (*_MSC, "    return value == FILLER  # 값이 정확히 FILLER일 때만",
                                              "    return True  #",
                                              [_T + "test_span_declared_on_a_raw_secret_is_caught_by_both_checks"]),
    # 재스캔: 면제를 span과 무관하게 FILLER 리터럴 전역으로 → 선언 안 된 password=[MASKED] 통과
    "rescan_exempts_filler_globally": (*_MSC, "    content = body.content  # 재스캔 대상 원문\n",
                                       '    content = None if body.content is None else body.content.replace(FILLER, "")\n',
                                       [_T + "test_undeclared_filler_under_credential_name_is_still_rescanned"]),
    # integrity 전체 해제 → 재스캔만으로는 'span 위치가 FILLER 아님'을 못 잡는다
    "integrity_off": (*_SC, "        found += masked_span_check.check_body_invariants(body, f\"{where}.{side}.body\")\n",
                      "        found += []\n",
                      [_T + "test_span_on_non_filler_harmless_value_is_caught_by_integrity_only"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_masked_span_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], tmp_path / "mut" / "src", rel, old, new)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut" / "src"), str(REPO_ROOT)]),
           "PYTHONUTF8": "1"}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
