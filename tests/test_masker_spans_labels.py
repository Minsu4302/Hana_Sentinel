"""fixture 마스커-B1 — 본문 masked_spans 생산 · 모드별 라벨(`label_consistency`) · HMAC 키 · 유출 검사 정밀화.
(A) §2.2 Body 불변식, §2.3 matcher 문법·라벨 모드 규칙·매핑 테이블, §1.3 ⓕ.

'위조 거부'로 증명한다: 불변식 1~6을 어기는 span을 내려는 변환 버그, 같은 값 다른 라벨·다른 값 같은 라벨, strict의
non-null 라벨은 마스커가 출력하지 않는다(자체 검증). HMAC 키는 출력·로그·예외 어디에도 없고 실행 끝에 버려진다.
label_consistency 검증은 relation_preserving 데이터로만 한다 — strict는 라벨이 전부 null이라 양방향 동치가 자명하게
성립하므로 그것으로 enforced를 주장하지 않는다(공허한 보장 금지). 엔진 ①②③ 교차 검증은 마스커-B2.
원본은 실행 중에만 만든다(N5 — faketoken_…·*.example.test, 레포 밖 임시 경로).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import subprocess
import sys
import traceback
import uuid
from pathlib import Path

import pytest

import tools.fixture_masker.masker as masker
from sentinel.common_types import FILLER
from sentinel.pipeline.schema_gate import parse_envelope
from tools.fixture_masker.masker import MaskerRejected
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PW = "pass" + "word"  # 리터럴 조립(시크릿 스캔 오탐 방지)


def _tok() -> str:
    return f"faketoken_{secrets.token_hex(8)}"


def _tx(headers=None, body=None, params=None, resp_body=None) -> dict:
    return {
        "meta": {"transaction_id": str(uuid.uuid4()), "captured_at": "2026-10-27T10:00:00+09:00", "origin_ref": "burp-1"},
        "request": {"method": "POST", "scheme": "http", "host": f"api-{secrets.token_hex(4)}.example.test", "port": 3000,
                    "path": "/rest/user/login", "query_params": params or [], "headers": headers or [],
                    "body": body or {"content_type": "text/plain", "encoding": "utf8", "content": "x"}},
        "response": {"status": 200, "headers": [],
                     "body": resp_body or {"content_type": "text/plain", "encoding": "utf8", "content": "ok"},
                     "elapsed_ms": 5}}


def _json_body(doc) -> dict:
    return {"content_type": "application/json", "encoding": "utf8", "content": json.dumps(doc)}


def _form_body(content: str) -> dict:
    return {"content_type": "application/x-www-form-urlencoded", "encoding": "utf8", "content": content}


def _mask(tmp_path: Path, txs: list[dict], mode: str = "strict_redaction") -> list[dict]:
    raw = tmp_path / "raw" / f"{uuid.uuid4().hex}.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"schema_version": "1.0", "transactions": txs}), encoding="utf-8")
    out = tmp_path / "out" / raw.stem
    masker.run(raw, out, mode)
    envs = [json.loads(p.read_bytes()) for p in sorted(out.iterdir())]
    for p in out.iterdir():
        parse_envelope(p.read_bytes())  # ② 스키마로 읽힘
    by_id = {e["transactions"][0]["meta"]["transaction_id"]: e["transactions"][0] for e in envs}
    return [by_id[t["meta"]["transaction_id"]] for t in txs]


def _rejected(tmp_path: Path, txs: list[dict], mode: str = "strict_redaction") -> str:
    with pytest.raises(MaskerRejected) as exc:
        _mask(tmp_path, txs, mode)
    return exc.value.code


# ── 본문 masked_spans 생산 ──────────────────────────────────────────

def test_json_rules_match_nested_members_at_any_depth_and_replace_in_place(tmp_path):
    t1, t2 = _tok(), _tok()
    body = _json_body({"user": {PW: t1, "name": "alice"}, "items": [{"api_key": t2}], "token": 12345})
    [tx] = _mask(tmp_path, [_tx(body=body)])
    out = tx["request"]["body"]
    doc = json.loads(out["content"])
    assert doc == {"user": {PW: FILLER, "name": "alice"}, "items": [{"api_key": FILLER}], "token": 12345}
    assert [s["at"] for s in out["masked_spans"]] == [{"kind": "json", "path": "/items/0/api_key", "range": None},
                                                      {"kind": "json", "path": f"/user/{PW}", "range": None}]
    assert out["size_bytes"] == len(out["content"].encode()) and out["truncated"] is False


def test_form_rules_mask_body_values_with_exact_ranges_and_form_params(tmp_path):
    t1, t2 = _tok(), _tok()
    content = f"user=alice&{PW}={t1}&csrf_token={t2}&remember=on"
    params = [{"name": "user", "value": "alice", "location": "form"}, {"name": PW, "value": t1, "location": "form"},
              {"name": "csrf_token", "value": t2, "location": "form"}, {"name": "q", "value": "apple", "location": "query"}]
    [tx] = _mask(tmp_path, [_tx(body=_form_body(content), params=params)])
    out = tx["request"]["body"]
    assert out["content"] == f"user=alice&{PW}={FILLER}&csrf_token={FILLER}&remember=on"
    for span in out["masked_spans"]:
        r = span["at"]["range"]
        assert span["at"]["kind"] == "text" and out["content"][r["start"]:r["end"]] == FILLER
    assert [s["at"]["range"]["start"] for s in out["masked_spans"]] == sorted(
        s["at"]["range"]["start"] for s in out["masked_spans"])
    masked_params = {p["name"] for p in tx["request"]["query_params"] if isinstance(p["value"], dict)}
    assert masked_params == {PW, "csrf_token"}


def test_body_declared_json_but_not_strict_json_is_rejected_fail_closed(tmp_path):
    body = {"content_type": "application/json", "encoding": "utf8", "content": f'{{"{PW}": "{_tok()}", "{PW}": "x"}}'}
    assert _rejected(tmp_path, [_tx(body=body)]) == "body_unparseable"


def test_text_body_without_rules_is_left_alone(tmp_path):
    [tx] = _mask(tmp_path, [_tx(body={"content_type": "text/plain", "encoding": "utf8", "content": "hello world"})])
    assert tx["request"]["body"]["content"] == "hello world" and tx["request"]["body"]["masked_spans"] == []


# ── 위조 거부: 불변식 1~6을 어기는 span을 내려는 변환 버그 → 출력하지 않음 ───────────

def _form_bug(kind: str):
    def bug(content, globs, run):
        content = f"{PW}={FILLER}&x={FILLER}"
        a = {"kind": "text", "range": {"start": len(PW) + 1, "end": len(PW) + 1 + len(FILLER)}}
        b = {"kind": "text", "range": {"start": content.rindex(FILLER), "end": len(content)}}
        ref = run.masked("v" + secrets.token_hex(4), "token")
        spans = {
            "inv2_text_without_range": [{"at": {"kind": "text"}, "ref": ref}],
            "inv3_offset_off_by_one": [{"at": {"kind": "text", "range": {"start": a["range"]["start"] + 1,
                                                                         "end": a["range"]["end"] + 1}}, "ref": ref}],
            "inv3_range_wrong_length": [{"at": {"kind": "text", "range": {"start": a["range"]["start"],
                                                                          "end": a["range"]["end"] - 1}}, "ref": ref}],
            "inv5_duplicate": [{"at": a, "ref": ref}, {"at": a, "ref": ref}],
            "inv6_out_of_order": [{"at": b, "ref": ref}, {"at": a, "ref": ref}],
        }[kind]
        return content, spans
    return bug


@pytest.mark.parametrize("kind", ["inv2_text_without_range", "inv3_offset_off_by_one", "inv3_range_wrong_length",
                                  "inv5_duplicate", "inv6_out_of_order"])
def test_masker_refuses_to_emit_text_spans_breaking_body_invariants(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(masker, "_mask_form", _form_bug(kind))
    out = tmp_path / "out"
    with pytest.raises(MaskerRejected) as exc:
        _mask(tmp_path, [_tx(body=_form_body(f"{PW}={_tok()}"))])
    assert exc.value.code == "span_invariant_violated"
    assert not out.exists()


def _json_bug(kind: str):
    def bug(content, globs, run):
        ref = run.masked("v" + secrets.token_hex(4), "token")
        if kind == "inv3_node_not_filler":
            return content, [{"at": {"kind": "json", "path": "/note"}, "ref": ref}]
        if kind == "inv5_node_and_range_same_node":
            content = json.dumps({"a": FILLER})
            return content, [{"at": {"kind": "json", "path": "/a"}, "ref": ref},
                             {"at": {"kind": "json", "path": "/a", "range": {"start": 0, "end": 8}}, "ref": ref}]
        if kind == "inv3_path_missing":
            return content, [{"at": {"kind": "json", "path": "/nope"}, "ref": ref}]
        raise AssertionError(kind)
    return bug


@pytest.mark.parametrize("kind", ["inv3_node_not_filler", "inv5_node_and_range_same_node", "inv3_path_missing"])
def test_masker_refuses_to_emit_json_spans_breaking_body_invariants(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(masker, "_mask_json", _json_bug(kind))
    with pytest.raises(MaskerRejected) as exc:
        _mask(tmp_path, [_tx(body=_json_body({"note": "plain"}))])
    assert exc.value.code == "span_invariant_violated"


def test_masker_refuses_spans_on_base64_body_invariant1(tmp_path, monkeypatch):
    real = masker._body

    def bug(b, run, globs):
        out = real(b, run, globs)
        out.update(encoding="base64", content=base64.b64encode(b"x").decode(),
                   masked_spans=[{"at": {"kind": "text", "range": {"start": 0, "end": 8}},
                                  "ref": run.masked("v" + secrets.token_hex(4), "token")}])
        return out
    monkeypatch.setattr(masker, "_body", bug)
    assert _rejected(tmp_path, [_tx()]) == "span_invariant_violated"


# ── label_consistency — relation_preserving 데이터로만 ─────────────────────

def test_relation_mode_same_value_same_label_across_header_body_and_param(tmp_path):
    shared, other = _tok(), _tok()
    tx = _tx(headers=[{"name": "X-Api-Key", "value": shared}, {"name": "X-Auth-Token", "value": other}],
             body=_json_body({"api_key": shared, "nested": {"session_id": other}}),
             resp_body=_json_body({"refresh_token": shared}))
    [out] = _mask(tmp_path, [tx], "relation_preserving")
    hdr = {h["name"]: h["value"]["label"] for h in out["request"]["headers"]}
    req = {s["at"]["path"]: s["ref"]["label"] for s in out["request"]["body"]["masked_spans"]}
    resp = {s["at"]["path"]: s["ref"]["label"] for s in out["response"]["body"]["masked_spans"]}
    assert hdr["X-Api-Key"] == req["/api_key"] == resp["/refresh_token"]       # 같은 원본값 → 같은 라벨(kind 무관)
    assert hdr["X-Auth-Token"] == req["/nested/session_id"]
    assert hdr["X-Api-Key"] != hdr["X-Auth-Token"]                             # 다른 원본값 → 다른 라벨


def test_relation_mode_labels_are_a_bijection_over_many_distinct_values(tmp_path):
    """150개 서로 다른 값 → 150개 서로 다른 라벨, 반복 값은 같은 라벨. 해시를 잘라 라벨로 쓰면 여기서 충돌한다."""
    values = [_tok() for _ in range(150)]
    body = _json_body({"items": [{"api_key": v} for v in values] + [{"api_key": values[0]}]})
    [out] = _mask(tmp_path, [_tx(body=body)], "relation_preserving")
    labels = {s["at"]["path"]: s["ref"]["label"] for s in out["request"]["body"]["masked_spans"]}
    by_value: dict[str, str] = {}
    for i, v in enumerate(values + [values[0]]):
        by_value.setdefault(v, labels[f"/items/{i}/api_key"])
        assert by_value[v] == labels[f"/items/{i}/api_key"]
    assert len(set(by_value.values())) == len(values)


def test_labels_are_scoped_to_one_run(tmp_path):
    shared = _tok()
    tx = lambda: _tx(headers=[{"name": "X-Api-Key", "value": shared}])  # noqa: E731
    [a] = _mask(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}]), tx()], "relation_preserving")[1:]
    [b] = _mask(tmp_path, [tx()], "relation_preserving")
    assert a["request"]["headers"][0]["value"]["label"] == "ref_02" and b["request"]["headers"][0]["value"]["label"] == "ref_01"


@pytest.mark.parametrize("bug", ["same_value_new_label", "different_values_one_label"])
def test_label_self_check_rejects_inconsistent_relation_labels(tmp_path, monkeypatch, bug):
    counter = iter(range(1, 1000))
    if bug == "same_value_new_label":
        monkeypatch.setattr(masker._Run, "_label", lambda self, digest: f"ref_{next(counter):02d}")
    else:
        monkeypatch.setattr(masker._Run, "_label", lambda self, digest: "ref_01")
    shared = _tok()
    tx = _tx(headers=[{"name": "X-Api-Key", "value": shared}, {"name": "X-Auth-Token", "value": _tok()}],
             body=_json_body({"api_key": shared}))
    assert _rejected(tmp_path, [tx], "relation_preserving") == "label_rule_violated"


# ── 모드 규칙: strict → label=null ─────────────────────────────────────

def test_strict_mode_labels_are_all_null_and_output_parses(tmp_path):
    shared = _tok()
    tx = _tx(headers=[{"name": "X-Api-Key", "value": shared}], body=_json_body({"api_key": shared}))
    [out] = _mask(tmp_path, [tx])
    refs = [h["value"] for h in out["request"]["headers"]] + [s["ref"] for s in out["request"]["body"]["masked_spans"]]
    assert refs and all(r["label"] is None for r in refs)


def test_strict_mode_rejects_a_non_null_label(tmp_path, monkeypatch):
    monkeypatch.setattr(masker._Run, "_label", lambda self, digest: "ref_01")
    assert _rejected(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}])]) == "label_rule_violated"


def test_mode_is_a_run_option_not_an_input_field(tmp_path):
    doc = {"schema_version": "1.0", "mode": "relation_preserving", "transactions": [_tx()]}
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(MaskerRejected) as exc:
        masker.load_raw(raw)
    assert exc.value.code == "raw_schema_invalid"
    with pytest.raises(MaskerRejected) as exc:
        masker.mask(masker.load_raw(_write(tmp_path)), "relation")
    assert exc.value.code == "unknown_mode"


def _write(tmp_path: Path) -> Path:
    raw = tmp_path / "ok.json"
    raw.write_text(json.dumps({"schema_version": "1.0", "transactions": [_tx()]}), encoding="utf-8")
    return raw


# ── HMAC 키: 실행마다 새로, 어디에도 남지 않고, 끝나면 버린다 ─────────────────────

KEY_MARKER = b"HMACKEYMARKER-" + b"k" * 18  # 32바이트, 출력 어디에 섞여도 눈에 띄는 형태


def _key_forms() -> list[str]:
    return [KEY_MARKER.decode(), KEY_MARKER.hex(), base64.b64encode(KEY_MARKER).decode(), "HMACKEYMARKER"]


@pytest.fixture
def runs(monkeypatch):
    created: list = []

    class Spy(masker._Run):
        def __init__(self, mode):
            super().__init__(mode)
            created.append((self, self.key))
    monkeypatch.setattr(masker, "_Run", Spy)
    return created


def test_hmac_key_is_fresh_per_run_and_discarded_at_the_end(tmp_path, runs):
    _mask(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}])], "relation_preserving")
    _mask(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}])], "relation_preserving")
    (r1, k1), (r2, k2) = runs
    assert len(k1) == len(k2) == 32 and k1 != k2
    assert r1.key is None and r2.key is None and not r1.table and not r1.emitted and not r1.originals


def test_hmac_key_is_discarded_even_when_the_run_fails(tmp_path, runs, monkeypatch):
    monkeypatch.setattr(masker._Run, "_label", lambda self, digest: "ref_01")
    _rejected(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}])])
    [(r, _)] = runs
    assert r.key is None


def test_hmac_key_never_reaches_output_logs_streams_or_exceptions(tmp_path, monkeypatch, caplog, capsys):
    monkeypatch.setattr(masker.secrets, "token_bytes", lambda n: KEY_MARKER)
    with caplog.at_level(logging.DEBUG):
        txs = _mask(tmp_path, [_tx(headers=[{"name": "X-Api-Key", "value": _tok()}],
                                   body=_json_body({"api_key": _tok()}))], "relation_preserving")
    blob = json.dumps(txs) + "".join(r.getMessage() + repr(r.__dict__) for r in caplog.records)
    captured = capsys.readouterr()
    blob += captured.out + captured.err
    files = b"".join(p.read_bytes() for p in (tmp_path / "out").rglob("*.json")).decode()
    monkeypatch.setattr(masker, "_mask_json", lambda *a: (_ for _ in ()).throw(ValueError(KEY_MARKER.hex())))
    with pytest.raises(MaskerRejected) as exc:
        _mask(tmp_path, [_tx(body=_json_body({"api_key": _tok()}))], "relation_preserving")
    blob += files + "".join(traceback.format_exception(exc.value))
    assert not any(form in blob for form in _key_forms())


# ── 유출 검사 정밀화: 비밀 아닌 조각의 과잉 거부만 줄이고, 마스킹 값은 여전히 잡는다 ─────────

def test_long_cookie_name_or_scheme_elsewhere_is_no_longer_over_rejected(tmp_path):
    """마스커-A는 8자 이상 조각(쿠키 이름 'trackingsession'·스킴 'Negotiate')이 다른 자리에 있어도 거부했다."""
    tx = _tx(headers=[{"name": "Cookie", "value": f"trackingsession={_tok()}"},
                      {"name": "Authorization", "value": f"Negotiate {_tok()}"}],
             resp_body={"content_type": "text/plain", "encoding": "utf8",
                        "content": "trackingsession cookie set via Negotiate"})
    [out] = _mask(tmp_path, [tx])
    assert out["response"]["body"]["content"] == "trackingsession cookie set via Negotiate"


@pytest.mark.parametrize("place", ["cookie_value_in_body", "credential_in_query", "body_secret_in_header",
                                   "form_value_encoded_in_query"])
def test_masked_values_left_elsewhere_are_still_rejected(tmp_path, place):
    tok = _tok()
    if place == "cookie_value_in_body":
        tx = _tx(headers=[{"name": "Cookie", "value": f"sid={tok}; theme=dark"}],
                 body={"content_type": "text/plain", "encoding": "utf8", "content": f"echo {tok}"})
    elif place == "credential_in_query":  # 큐 13: query 규칙 없음 → 마스킹된 값이 남으면 거부(fail-closed)
        tx = _tx(headers=[{"name": "Authorization", "value": f"Bearer {tok}"}],
                 params=[{"name": "t", "value": tok, "location": "query"}])
    elif place == "body_secret_in_header":
        tx = _tx(headers=[{"name": "X-Trace", "value": tok}], body=_json_body({PW: tok}))
    else:
        tx = _tx(body=_form_body(f"{PW}=a%2B{tok}"), params=[{"name": "x", "value": f"a%2B{tok}", "location": "query"}])
    assert _rejected(tmp_path, [tx]) == "masked_value_leaked"


# ── 변이 확인: 각 장치가 하중을 지지한다(변이본 로드 먼저 증명) ───────────────────────

STAMP = "masker_b1_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_masker_spans_labels.py::"
_M = ("tools/fixture_masker/masker.py", "tools.fixture_masker.masker")
MUTATIONS = {
    "label_from_truncated_hash": (*_M, '            self.table[digest] = f"ref_{n:02d}"  # 순번 할당 — 해시를 잘라 쓰지 않는다',
                                  '            self.table[digest] = f"ref_{digest[0] % 100:02d}"  #',
                                  [_T + "test_relation_mode_labels_are_a_bijection_over_many_distinct_values"]),
    "label_self_check_off": (*_M, "        if not _labels_ok(run):\n", "        if False:\n",
                             [_T + "test_label_self_check_rejects_inconsistent_relation_labels",
                              _T + "test_strict_mode_rejects_a_non_null_label"]),
    "strict_label_null_off": (*_M, "            return None  # (A) §2.3: strict_redaction → label=null", "            pass  #",
                              [_T + "test_strict_mode_labels_are_all_null_and_output_parses"]),
    "span_self_check_off": (*_M, "        if not all(_spans_ok(", "        if False and not all(_spans_ok(",
                            [_T + "test_masker_refuses_to_emit_text_spans_breaking_body_invariants",
                             _T + "test_masker_refuses_to_emit_json_spans_breaking_body_invariants",
                             _T + "test_masker_refuses_spans_on_base64_body_invariant1"]),
    "key_not_discarded": (*_M, "        self.key = None\n", "        pass\n",
                          [_T + "test_hmac_key_is_fresh_per_run_and_discarded_at_the_end",
                           _T + "test_hmac_key_is_discarded_even_when_the_run_fails"]),
    "leak_parts_dropped": (*_M, "        found.update(p for p in _secret_parts(o) if len(p) >= MIN_FRAGMENT)\n", "        pass\n",
                           [_T + "test_masked_values_left_elsewhere_are_still_rejected",
                            "tests/test_fixture_masker.py::test_masked_value_also_present_in_unmasked_place_is_rejected_fail_closed"]),
    "leak_form_encoded_dropped": (*_M, "            run.originals.append(raw_value)  # 인코딩된 형태도 유출 검사 대상\n", "",
                                  [_T + "test_masked_values_left_elsewhere_are_still_rejected"]),
    "json_rules_top_level_only": (*_M, "            if key is not None and _matches(key, globs)]",
                                  "            if key is not None and p.count('/') == 1 and _matches(key, globs)]",
                                  [_T + "test_json_rules_match_nested_members_at_any_depth_and_replace_in_place"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_b1_mechanism_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", rel, old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
