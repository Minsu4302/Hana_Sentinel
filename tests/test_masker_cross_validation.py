"""마스커 ↔ 엔진 교차 검증 — 마스커 출력이 엔진의 실제 ②③을 통과하고, 틀린 출력은 ③이 거부한다(순환 아님 증명).
기존 키(`input_schema_gate`·`sanitization_trust`·`masked_span_integrity`)가 마스커 출력에도 성립함을 보이는 것이다 —
새 강제가 아니라 기존 강제의 적용 확인.

교차 검증이지 순환이 아닌 이유:
- 마스커는 엔진 검증 파이프라인(`sentinel.pipeline`)을 import하지 않는다 — 정적(`masker_independence`)으로도,
  실행 중 import 그래프로도(base64 판정 경로를 실제로 태워서) 확인한다.
- 둘이 공유하는 것은 정책 데이터(`sanitization_policy.PATTERNS` — '무엇을 찾나')뿐이다. 스캔·판정 로직은 따로 있다:
  base64 본문에서 마스커 `_finds_secret`과 엔진 `check_body`가 같은 패턴·같은 디코드 바이트로 각자 판정하고 같은
  결론(비밀 있음/없음)에 이르는지를 표본마다 본다. 같은 로직을 두 번 부르고 '독립'이라 부르지 않는다.
- base64 디코드·퍼센트 디코드 자체는 표준 라이브러리라 양쪽이 같다(독립 아님 — 정직 표기). 독립의 실체는 판정 로직이다.
- 반대 방향: 일부러 틀리게 마스킹한 출력(span 위치 생문자열, base64 미판정, 정책 헤더 평문, 선언 없는 FILLER)과
  마스커 규칙 밖의 비밀(규칙에 없는 필드의 JWT)을 엔진 ③이 거부한다 — 엔진이 마스커 출력을 무조건 통과시키지 않으며,
  마스커의 커버 공백을 ③이 2차로 메운다(R-11 2단 방어).
원본은 실행 중에만 만든다(N5 — faketoken_…·*.example.test, 레포 밖 임시 경로). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import ast
import base64
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

import tools.fixture_masker.masker as masker
from sentinel import sanitization_policy
from sentinel.common_types import FILLER
from sentinel.pipeline import sanitization_check
from sentinel.schema import Body
from tests.test_masker_spans_labels import PW, _form_body, _json_body, _tok, _tx
from tools.masker_cross_check import engine_verdict
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
MODES = ["strict_redaction", "relation_preserving"]


def _jwt() -> str:
    return "eyJ" + "h" * 12 + "." + "eyJ" + "p" * 12 + "." + "s" * 16


def _b64_body(data: bytes, ctype: str = "application/octet-stream") -> dict:
    return {"content_type": ctype, "encoding": "base64", "content": base64.b64encode(data).decode()}


def _masked_files(tmp_path: Path, txs: list[dict], mode: str) -> list[bytes]:
    raw = tmp_path / "raw" / f"{uuid.uuid4().hex}.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"schema_version": "1.0", "transactions": txs}), encoding="utf-8")
    out = tmp_path / "out" / raw.stem
    masker.run(raw, out, mode)
    return [p.read_bytes() for p in sorted(out.iterdir())]


# ── 정상 범주: 마스커 출력 → 엔진 ②③ 통과 ─────────────────────────────────

def _categories() -> dict[str, dict]:
    return {
        "policy_headers": _tx(headers=[{"name": "Cookie", "value": f"sid={_tok()}"},
                                       {"name": "Authorization", "value": f"Bearer {_tok()}"},
                                       {"name": "X-Api-Key", "value": _tok()}, {"name": "Host", "value": "a.example.test"}]),
        "json_nested_spans": _tx(body=_json_body({"user": {PW: _tok(), "name": "alice"},
                                                  "items": [{"access_token": _tok()}], "session": {"id": 1}})),
        "form_spans_and_params": _tx(body=_form_body(f"user=alice&{PW}={_tok()}&remember=on"),
                                     params=[{"name": PW, "value": "x" + _tok(), "location": "form"}]),
        "base64_with_secret_omitted": _tx(body=_b64_body(f"Authorization: Bearer {_tok()}".encode())),
        "base64_clean_preserved": _tx(body=_b64_body(bytes(range(32)) + b"plain binary")),
        "response_json_span": _tx(resp_body=_json_body({"refresh_token": _tok(), "ok": True})),
    }


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("category", sorted(_categories()))
def test_masker_output_passes_engine_schema_and_sanitization(tmp_path, category, mode):
    [out] = _masked_files(tmp_path, [_categories()[category]], mode)
    assert engine_verdict(out) == ("accepted", ())


def test_base64_bodies_are_judged_omitted_or_preserved(tmp_path):
    cats = _categories()
    [secret] = _masked_files(tmp_path, [cats["base64_with_secret_omitted"]], "strict_redaction")
    [clean] = _masked_files(tmp_path, [cats["base64_clean_preserved"]], "strict_redaction")
    s_body = json.loads(secret)["transactions"][0]["request"]["body"]
    c_body = json.loads(clean)["transactions"][0]["request"]["body"]
    assert (s_body["encoding"], s_body["content"], s_body["masked_spans"], s_body["truncated"]) == ("omitted", None, [], False)
    assert s_body["size_bytes"] > 0  # 원본(디코드) 크기
    raw_clean = cats["base64_clean_preserved"]["request"]["body"]["content"]
    assert (c_body["encoding"], c_body["content"]) == ("base64", raw_clean)


def test_base64_secret_bytes_never_reach_output_or_logs(tmp_path, caplog):
    tok = _tok()
    with caplog.at_level("DEBUG"):
        [out] = _masked_files(tmp_path, [_tx(body=_b64_body(f"Bearer {tok}".encode()))], "strict_redaction")
    encoded = base64.b64encode(f"Bearer {tok}".encode()).decode()
    blob = out.decode() + "".join(r.getMessage() + repr(r.__dict__) for r in caplog.records)
    assert tok not in blob and encoded not in blob


# ── 순환 아님: import 그래프 · 독립 판정 로직의 동등성 ──────────────────────────

def test_patterns_are_shared_policy_data_not_pipeline_code():
    assert sanitization_check.PATTERNS is sanitization_policy.PATTERNS  # 재노출 — ③은 정책 데이터를 쓴다
    assert masker.PATTERNS is sanitization_policy.PATTERNS
    assert masker._finds_secret is not sanitization_check.scan_text
    tree = ast.parse(Path(masker.__file__).read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree)
                                                                       if isinstance(n, ast.Attribute)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert not names & {"scan_text", "check_body", "check_transaction", "verify_sanitization"}


_GRAPH = """
import os, sys, base64, json, uuid
if sys.path[0] in ("", os.getcwd()):
    sys.path.pop(0)  # -c가 넣은 현재 디렉터리(레포 루트)만 뺀다 — PYTHONPATH 항목은 남긴다
from tools.fixture_masker import masker
from tools.fixture_masker.raw import RawEnvelope
tx = {"meta": {"transaction_id": str(uuid.uuid4()), "captured_at": "2026-10-27T10:00:00+09:00", "origin_ref": "b"},
      "request": {"method": "GET", "scheme": "http", "host": "a.example.test", "port": 80, "path": "/", "query_params": [],
                  "headers": [], "body": {"content_type": "application/octet-stream", "encoding": "base64",
                                          "content": base64.b64encode(sys.argv[1].encode()).decode()}},
      "response": {"status": 200, "headers": [], "body": {"content_type": "text/plain", "encoding": "utf8",
                                                          "content": "ok"}, "elapsed_ms": 1}}
masker.mask(RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": [tx]})))
print(json.dumps(sorted(m for m in sys.modules if m == "sentinel.pipeline" or m.startswith("sentinel.pipeline."))))
"""


def test_masker_runtime_import_graph_has_no_engine_pipeline_even_on_the_base64_path():
    """정적 검사(masker_independence)와 별도로, base64 판정 경로를 실제로 태운 뒤 로드된 모듈에 pipeline이 없다."""
    root = Path(masker.__file__).resolve().parents[2]  # 실제 로드된 마스커의 루트(변이 실행에서는 변이본)
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONPATH": os.pathsep.join([str(root), str(REPO_ROOT / "src")])}
    r = subprocess.run([sys.executable, "-c", _GRAPH, f"Bearer {_tok()}"], cwd=REPO_ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == []


def _samples() -> dict[str, bytes]:
    tok = _tok()
    return {
        "bearer": f"Authorization: Bearer {tok}".encode(),
        "jwt": f"token={_jwt()}".encode(),
        "percent_encoded_credential": f"a=1&pass%77ord={tok}".encode(),          # 퍼센트 디코드 변형에서만 걸림
        "plus_encoded_scheme": f"Bearer+{tok}".encode(),                         # '+' → 공백 변형에서만 걸림
        "invalid_utf8_around_secret": b"\xff\xfe" + f" Bearer {tok} ".encode() + b"\xc3",
        "clean_text_with_percent": b"discount 100% off + free shipping",
        "clean_binary": bytes(range(256)),
        "almost_secret": b"Bearer short",
    }


@pytest.mark.parametrize("name", sorted(_samples()))
def test_two_independent_matchers_reach_the_same_verdict_on_the_same_decoded_bytes(name):
    data = _samples()[name]
    masker_says = masker._finds_secret(data.decode("utf-8", errors="replace"))
    body = Body(content_type="application/octet-stream", size_bytes=len(data), truncated=False, encoding="base64",
                content=base64.b64encode(data).decode())
    engine_says = any(r.endswith(".decoded") for r in sanitization_check.check_body(body, "b", 10 ** 6))
    assert masker_says == engine_says
    expected = name not in {"clean_text_with_percent", "clean_binary", "almost_secret"}
    assert masker_says is expected  # 표본 자체가 의도대로(비밀 있음/없음)인지 — 둘 다 틀리는 경우를 막는다


# ── 반대 방향: 틀린 출력·규칙 밖 비밀 → 엔진 ③ 거부 ─────────────────────────────

def _tamper(out: bytes, edit) -> bytes:
    doc = json.loads(out)
    edit(doc["transactions"][0])
    return json.dumps(doc, ensure_ascii=False).encode()


def test_engine_rejects_raw_secret_put_back_at_a_declared_span(tmp_path):
    tok = _tok()
    [out] = _masked_files(tmp_path, [_tx(body=_json_body({PW: tok}))], "strict_redaction")
    bad = _tamper(out, lambda tx: tx["request"]["body"].update(content=json.dumps({PW: tok})))
    verdict, reasons = engine_verdict(bad)
    assert verdict == "sanitization_rejected" and {"masked_span_not_filler", "credential_json_field"} <= set(reasons)


def test_engine_rejects_base64_secret_the_masker_failed_to_judge(tmp_path, monkeypatch):
    monkeypatch.setattr(masker, "_finds_secret", lambda text: False)  # 마스커 base64 판정 누락(모의)
    [out] = _masked_files(tmp_path, [_tx(body=_b64_body(f"Authorization: Bearer {_tok()}".encode()))], "strict_redaction")
    assert json.loads(out)["transactions"][0]["request"]["body"]["encoding"] == "base64"  # 마스커 자체 검증은 못 봄
    assert engine_verdict(out) == ("sanitization_rejected", ("auth_scheme_credential",))


def test_engine_rejects_policy_header_the_masker_left_plaintext(tmp_path, monkeypatch):
    monkeypatch.setattr(masker, "_header_kind", lambda name: None)  # 헤더 정책 누락(모의) — 마스커 유출 검사는 모름
    [out] = _masked_files(tmp_path, [_tx(headers=[{"name": "Authorization", "value": f"Bearer {_tok()}"}])],
                          "strict_redaction")
    verdict, reasons = engine_verdict(out)
    assert verdict == "sanitization_rejected" and {"plaintext_sensitive_header", "auth_scheme_credential"} <= set(reasons)


def test_engine_rejects_undeclared_filler_left_after_a_span_is_dropped(tmp_path):
    [out] = _masked_files(tmp_path, [_tx(body=_form_body(f"user=alice&{PW}={_tok()}"))], "strict_redaction")
    bad = _tamper(out, lambda tx: tx["request"]["body"].update(masked_spans=[]))
    assert engine_verdict(bad) == ("sanitization_rejected", ("credential_form_field",))


def test_engine_rejects_a_span_moved_off_the_filler(tmp_path):
    [out] = _masked_files(tmp_path, [_tx(body=_form_body(f"user=alice&{PW}={_tok()}"))], "strict_redaction")

    def shift(tx):
        tx["request"]["body"]["masked_spans"][0]["at"]["range"] = {"start": 0, "end": len(FILLER)}
    verdict, reasons = engine_verdict(_tamper(out, shift))
    assert verdict == "sanitization_rejected" and "masked_span_not_filler" in reasons


def test_engine_covers_the_masker_rule_gap(tmp_path):
    """규칙에 없는 필드(note)의 JWT: 마스커는 비밀로 모르고 내보낸다 → 엔진 ③이 독립으로 거부(2단 방어)."""
    [out] = _masked_files(tmp_path, [_tx(body=_json_body({"note": _jwt(), PW: _tok()}))], "relation_preserving")
    assert json.loads(out)["transactions"][0]["request"]["body"]["masked_spans"]  # 규칙 안의 값은 마스킹됨
    assert engine_verdict(out) == ("sanitization_rejected", ("jwt",))


# ── 변이 확인 ──────────────────────────────────────────────────────

STAMP = "masker_cross_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]  # 레포 루트의 원본 tools/가 변이본을 가리지 않게
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_masker_cross_validation.py::"
_M = ("tools/fixture_masker/masker.py", "tools.fixture_masker.masker")
_C = ("tools/masker_cross_check.py", "tools.masker_cross_check")
MUTATIONS = {
    "base64_scan_off": (*_M, "    return any(pattern.search(v) for v in variants for pattern in PATTERNS.values())\n",
                        "    return False\n",
                        [_T + "test_base64_bodies_are_judged_omitted_or_preserved",
                         _T + "test_masker_output_passes_engine_schema_and_sanitization"]),
    "base64_judgment_reuses_engine_scan": (*_M,
        '    variants = [text, unquote_plus(text)] if ("%" in text or "+" in text) else [text]\n'
        "    return any(pattern.search(v) for v in variants for pattern in PATTERNS.values())\n",
        "    from sentinel.pipeline.sanitization_check import scan_text  # 변이: 엔진 판정 로직 재사용\n"
        "    return bool(scan_text(text))\n",
        ["tests/test_fixture_masker.py::test_masker_does_not_import_engine_pipeline_but_uses_shared_strict_json",
         _T + "test_masker_runtime_import_graph_has_no_engine_pipeline_even_on_the_base64_path",
         _T + "test_patterns_are_shared_policy_data_not_pipeline_code"]),
    "cross_check_uses_masker_self_check": (*_C, "        sanitization_check.verify_sanitization(envelope)\n",
        "        from tools.fixture_masker.masker import _spans_ok  # 변이: 엔진 ③ 대신 마스커 자체 검증 재사용\n"
        "        if not all(_spans_ok(t.model_dump(mode='json')[s]['body']) for t in envelope.transactions\n"
        "                   for s in ('request', 'response')):\n"
        "            return 'sanitization_rejected', ('masker_self_check',)\n",
        [_T + "test_engine_rejects_base64_secret_the_masker_failed_to_judge",
         _T + "test_engine_rejects_policy_header_the_masker_left_plaintext",
         _T + "test_engine_covers_the_masker_rule_gap",
         _T + "test_engine_rejects_undeclared_filler_left_after_a_span_is_dropped"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_cross_validation_mechanism_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", rel, old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)  # 원본이 아니라 변이본이 돌았다
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
