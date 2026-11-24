"""2부 PR-1a — 동등성의 기준(Python 참조 구현) 고정. (A) v1.49 §2.2(size_bytes·절단·불변식 7), §2.3(정책 정본 파일·배치 범위·
object_id_rules), §2.6(TRUNCATION_MARK), §2.10(정규 직렬화).

'위조 거부'와 정의 일치로 증명한다:
- 정책: 정본은 JSON 파일 하나 — 규칙 값이 코드에 다시 적히면 실패, 중복 키 파일은 기동 거부, object_id_rules가 비어 있지 않으면 마스커가 거부.
- §2.10: 동결본(S v1·S v2) 재직렬화 바이트 일치 + 이스케이프·시각·UUID·정수만·생략 없음 규칙.
- 절단: 상한·앞뒤 예산·코드포인트 경계·FILLER 통째 버림·json span → text span·표지 든 원본 → omitted·base64 상한 → omitted.
- size_bytes: 마스킹된 본문·절단된 본문·base64·omitted 각각 정의와 일치.
- 배치: run은 데이터셋 생성기만 — 그 밖의 코드에서 쓰면 정적 검사가 잡는다(심은 위반으로 증명).
"""
from __future__ import annotations

import ast
import base64
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

from sentinel import canonical_json
from sentinel.common_types import FILLER, TRUNCATION_MARK
from sentinel.pipeline.sanitization_check import verify_sanitization
from sentinel.pipeline.schema_gate import parse_envelope
from sentinel.sanitization_policy import DEFAULT_POLICY, POLICY_PATH, ObjectIdRule, load_policy
from sentinel.schema import Envelope
from tools.fixture_masker import masker
from tools.fixture_masker.masker import TRUNCATE_LIMIT, MaskerRejected
from tools.fixture_masker.raw import RawEnvelope

REPO_ROOT = Path(__file__).resolve().parents[1]
MARK_LEN = len(TRUNCATION_MARK)
FROZEN_POLICY_VERSION = "python-recheck-1"  # 동결 S v1·S v2가 기록한 값(바꾸지 않는다)


# ─────────────────────────────── 공용
def _tx(req_body=None, resp_body=None, params=(), headers=()) -> dict:
    return {"meta": {"transaction_id": str(uuid.uuid4()), "captured_at": "2026-11-23T10:00:00+09:00", "origin_ref": "burp-1"},
            "request": {"method": "POST", "scheme": "http", "host": "api.example.test", "port": 3000, "path": "/rest/x",
                        "query_params": list(params), "headers": list(headers),
                        "body": req_body or {"content_type": "text/plain", "encoding": "utf8", "content": "x"}},
            "response": {"status": 200, "headers": [],
                         "body": resp_body or {"content_type": "text/plain", "encoding": "utf8", "content": "ok"},
                         "elapsed_ms": 5}}


def _text(content: str, ctype: str = "text/plain") -> dict:
    return {"content_type": ctype, "encoding": "utf8", "content": content}


def _mask_one(tx: dict, mode: str = "strict_redaction") -> dict:
    raw = RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": [tx]}))
    [(_name, data)] = masker.mask(raw, mode)
    verify_sanitization(parse_envelope(data))  # 엔진 ③이 받아들인다(불변식 1~7·재스캔)
    return json.loads(data)["transactions"][0]


def _secret() -> str:
    return "faketoken_" + uuid.uuid4().hex[:16]


# ─────────────────────────────── 정책 정본 파일
def test_default_policy_is_loaded_from_the_single_policy_file():
    assert POLICY_PATH.name == "sanitization_policy.json" and POLICY_PATH.parent == REPO_ROOT / "src" / "sentinel"
    assert DEFAULT_POLICY == load_policy(POLICY_PATH)
    doc = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    assert set(doc) == {"policy_version", "header_rules", "body_rules", "object_id_policy", "object_id_rules"}


def test_policy_version_was_raised_from_the_frozen_value():
    assert DEFAULT_POLICY.policy_version != FROZEN_POLICY_VERSION
    frozen = {json.loads(p.read_text(encoding="utf-8"))["transactions"][0]["meta"]["sanitization"]["policy_version"]
              for p in (REPO_ROOT / "datasets" / "S").rglob("*.json") if "transactions" in p.read_text(encoding="utf-8")}
    assert frozen == {FROZEN_POLICY_VERSION}  # 동결본은 그대로


def _rule_values() -> set[str]:
    return {r.name_pattern for r in DEFAULT_POLICY.header_rules} | {r.matcher for r in DEFAULT_POLICY.body_rules}


def rule_list_copies(roots: list[Path], threshold: int = 3) -> list[str]:
    """규칙 값이 한 파일의 문자열 상수로 threshold개 이상 다시 나오면 두 번째 규칙 목록으로 본다(주석은 보지 않는다).
    단어 하나(헤더 이름·kind 이름)의 우연한 일치는 목록이 아니다."""
    values, found = _rule_values(), []
    for root in roots:
        for path in root.rglob("*.py"):
            consts = {n.value for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                      if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            if len(values & consts) >= threshold:
                found.append(path.name)
    return found


def test_rule_values_are_not_written_again_in_code():
    """규칙 값의 정본은 파일 하나 — src·tools 코드에 규칙 목록이 다시 적히면 두 번째 정본이다."""
    assert rule_list_copies([REPO_ROOT / "src", REPO_ROOT / "tools"]) == []


def test_planted_second_rule_list_is_caught(tmp_path):
    pkg = tmp_path / "src"
    pkg.mkdir()
    (pkg / "copy.py").write_text('RULES = ("authorization", "*token*", "json:password", "form:pwd")\n', encoding="utf-8")
    assert rule_list_copies([pkg]) == ["copy.py"]


def test_policy_patterns_stay_out_of_the_policy_file():
    from sentinel.sanitization_policy import PATTERNS
    text = POLICY_PATH.read_text(encoding="utf-8")
    assert "patterns" not in json.loads(text) and not any(name in text for name in PATTERNS)


def test_policy_file_with_duplicate_key_is_refused(tmp_path):
    bad = tmp_path / "policy.json"
    bad.write_text('{"policy_version": "a", "policy_version": "b", "header_rules": []}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_policy(bad)


def test_object_id_rules_start_empty_and_non_empty_rules_are_refused_fail_closed(monkeypatch):
    assert DEFAULT_POLICY.object_id_rules == ()
    monkeypatch.setattr(masker, "POLICY", DEFAULT_POLICY.model_copy(
        update={"object_id_rules": (ObjectIdRule(matcher="query:id", action="pseudonymize"),)}))
    raw = RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": [_tx()]}))
    with pytest.raises(MaskerRejected) as exc:
        masker.mask(raw)
    assert exc.value.code == "object_id_rules_unsupported"


# ─────────────────────────────── §2.10 정규 직렬화
def _frozen_envelopes():
    for path in sorted((REPO_ROOT / "datasets" / "S").rglob("*.json")):
        data = path.read_bytes()
        if b'"transactions"' in data:
            yield path, data


def test_frozen_envelopes_reserialize_byte_identical_under_section_2_10():
    files = list(_frozen_envelopes())
    assert len(files) == 126
    assert [p.name for p, data in files if canonical_json.dumps(Envelope.model_validate_json(data)) != data] == []


@pytest.mark.parametrize("value,expected", [
    ('"', '"\\""'), ("\\", '"\\\\"'), ("\b\t\n\f\r", '"\\b\\t\\n\\f\\r"'), ("\x00\x01\x1f", '"\\u0000\\u0001\\u001f"'),
    ("/", '"/"'), ("\x7f", '"\x7f"'), ("é한😀", '"é한😀"'), ("  ", '"  "'),
])
def test_string_escapes_follow_section_2_10(value, expected):
    assert canonical_json.dumps(value) == expected.encode("utf-8")


@pytest.mark.parametrize("value,expected", [
    (datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc), "2026-11-23T10:00:00Z"),
    (datetime(2026, 11, 23, 10, 0, 0, 500000, tzinfo=timezone(timedelta(hours=9))), "2026-11-23T10:00:00.500000+09:00"),
    (datetime(2026, 11, 23, 10, 0, 0, 123, tzinfo=timezone(timedelta(hours=-5, minutes=-30))), "2026-11-23T10:00:00.000123-05:30"),
    (UUID("005E0000-0000-0040-0080-000000000001"), "005e0000-0000-0040-0080-000000000001"),
])
def test_datetime_and_uuid_notation_follow_section_2_10(value, expected):
    assert canonical_json.dumps(value) == f'"{expected}"'.encode()


@pytest.mark.parametrize("bad", [1.5, "\ud800", datetime(2026, 1, 1), {1: "x"}, object()])
def test_values_section_2_10_cannot_express_are_refused(bad):
    with pytest.raises(canonical_json.CanonicalError):
        canonical_json.dumps(bad)


def test_members_are_never_omitted_and_follow_declaration_order():
    env = Envelope.model_validate_json(next(_frozen_envelopes())[1])
    doc = json.loads(canonical_json.dumps(env))
    assert list(doc) == list(Envelope.model_fields)
    body = doc["transactions"][0]["response"]["body"]
    assert list(body) == ["content_type", "size_bytes", "truncated", "encoding", "content", "masked_spans"]
    assert json.dumps(None) == "null" and canonical_json.dumps([None, True, False, 0, -7]) == b"[null,true,false,0,-7]"


def test_masker_output_bytes_are_section_2_10():
    out = masker.mask(RawEnvelope.model_validate_json(json.dumps({"schema_version": "1.0", "transactions": [_tx()]})))
    [(_name, data)] = out
    assert data == canonical_json.dumps(Envelope.model_validate_json(data))


# ─────────────────────────────── 절단((A) §2.2, Body 불변식 7)
LIMIT = TRUNCATE_LIMIT["request"]
HEAD, TAIL = (LIMIT - MARK_LEN) // 2, (LIMIT - MARK_LEN) - (LIMIT - MARK_LEN) // 2


def test_limits_are_the_section_2_2_values():
    assert TRUNCATE_LIMIT == {"request": 64 * 1024, "response": 256 * 1024}


def test_body_at_or_under_the_limit_is_not_truncated():
    out = _mask_one(_tx(req_body=_text("a" * LIMIT)))["request"]["body"]
    assert (out["truncated"], out["size_bytes"], len(out["content"])) == (False, LIMIT, LIMIT)


def test_ascii_body_over_the_limit_keeps_exact_head_and_tail_budgets():
    content = "h" * 40000 + "t" * 40000
    out = _mask_one(_tx(req_body=_text(content)))["request"]["body"]
    assert out["truncated"] is True and out["size_bytes"] == 80000
    assert out["content"] == "h" * HEAD + TRUNCATION_MARK + "t" * TAIL
    assert len(out["content"].encode()) == LIMIT


def test_cut_points_move_inward_to_codepoint_boundaries():
    content = "한" * 30000  # 3바이트 문자
    out = _mask_one(_tx(req_body=_text(content)))["request"]["body"]
    head, tail = out["content"].split(TRUNCATION_MARK)
    assert len(head) == HEAD // 3 and len(tail) == TAIL // 3 and set(head + tail) == {"한"}
    assert len(out["content"].encode()) <= LIMIT


def _form(content: str) -> dict:
    return _text(content, "application/x-www-form-urlencoded")


def test_filler_on_the_head_cut_is_dropped_whole_and_still_counted():
    # 마스킹 뒤 FILLER가 HEAD-3 .. HEAD+5에 오도록 — 앞 경계가 FILLER 안에 떨어진다
    k = HEAD - 3 - len("pad=") - len("&password=")
    content = "pad=" + "a" * k + "&password=" + _secret() + "&q=" + "b" * 40000
    tx = _mask_one(_tx(req_body=_form(content)))
    body = tx["request"]["body"]
    assert body["truncated"] is True and body["masked_spans"] == []
    assert body["content"].index(TRUNCATION_MARK) == HEAD - 3   # 경계를 FILLER 시작으로 당김
    assert FILLER not in body["content"] and "[MAS" not in body["content"]
    assert tx["meta"]["sanitization"]["redacted_count"] == 1 and tx["meta"]["sanitization"]["redacted_kinds"]["token"] == 1


def test_filler_on_the_tail_cut_is_dropped_whole():
    content = "q=" + "b" * 40000 + "&password=" + _secret() + "&z=" + "c" * (TAIL - 7)
    body = _mask_one(_tx(req_body=_form(content)))["request"]["body"]
    tail = body["content"].split(TRUNCATION_MARK)[1]
    assert body["masked_spans"] == [] and FILLER not in body["content"] and tail.startswith("&z=")


def test_json_spans_become_text_ranges_on_the_filler_after_truncation():
    doc = {"password": _secret(), "data": "x" * 80000, "token": _secret()}
    body = _mask_one(_tx(req_body=_text(json.dumps(doc), "application/json")))["request"]["body"]
    assert body["truncated"] is True and len(body["masked_spans"]) == 2
    for span in body["masked_spans"]:
        rng = span["at"]["range"]
        assert span["at"]["kind"] == "text" and body["content"][rng["start"]:rng["end"]] == FILLER
    starts = [s["at"]["range"]["start"] for s in body["masked_spans"]]
    assert starts == sorted(starts)


def test_raw_body_already_containing_the_mark_is_sent_omitted():
    body = _mask_one(_tx(req_body=_text(f"log line {TRUNCATION_MARK} more")))["request"]["body"]
    assert (body["encoding"], body["content"], body["truncated"], body["size_bytes"]) == ("omitted", None, False, 0)


def test_base64_over_the_limit_is_omitted_not_truncated():
    data = bytes(range(256)) * 200  # 51200바이트 → base64 68268자 > 64KiB
    body = _mask_one(_tx(req_body={"content_type": "application/octet-stream", "encoding": "base64",
                                   "content": base64.b64encode(data).decode()}))["request"]["body"]
    assert (body["encoding"], body["content"], body["truncated"], body["size_bytes"]) == ("omitted", None, False, 0)


def test_response_limit_is_larger_than_request_limit():
    under = _mask_one(_tx(resp_body=_text("r" * 200000)))["response"]["body"]
    over = _mask_one(_tx(resp_body=_text("r" * 300000)))["response"]["body"]
    assert under["truncated"] is False and over["truncated"] is True
    assert len(over["content"].encode()) <= TRUNCATE_LIMIT["response"]


# ─────────────────────────────── size_bytes 정의((A) §2.2 v1.49)
def test_size_bytes_of_a_masked_body_is_the_masked_content_bytes():
    secret = _secret()
    content = json.dumps({"password": secret, "note": "한글"})
    body = _mask_one(_tx(req_body=_text(content, "application/json")))["request"]["body"]
    assert body["size_bytes"] == len(body["content"].encode()) != len(content.encode())


def test_size_bytes_of_a_truncated_body_is_the_masked_bytes_before_truncation():
    content = "pad=" + "a" * 70000 + "&password=" + _secret()
    masked_len = len(content.encode()) - len(content.split("&password=")[1]) + len(FILLER)
    body = _mask_one(_tx(req_body=_form(content)))["request"]["body"]
    assert body["truncated"] is True and body["size_bytes"] == masked_len


def test_size_bytes_of_base64_is_the_decoded_bytes():
    data = b"\x00\x01binary\xff" * 10
    body = _mask_one(_tx(req_body={"content_type": "application/octet-stream", "encoding": "base64",
                                   "content": base64.b64encode(data).decode()}))["request"]["body"]
    assert (body["encoding"], body["size_bytes"]) == ("base64", len(data))


def test_size_bytes_of_an_omitted_body_is_zero():
    body = _mask_one(_tx(req_body={"content_type": "image/png", "encoding": "omitted", "content": None}))["request"]["body"]
    assert (body["encoding"], body["size_bytes"]) == ("omitted", 0)


# ─────────────────────────────── 배치 범위: run은 데이터셋 생성기만
RUN_ALLOWED = {"tools/dataset/generator.py", "tools/dataset/build_s_v1.py"}


def run_batch_uses(roots: list[Path], base: Path) -> list[str]:
    """`batch`에 "transaction" 리터럴이 아닌 값을 주거나 mask()에 위치 인자 3개 이상을 주는 호출 — 파일 목록."""
    found = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(base).as_posix()
            if rel.startswith("tools/fixture_masker/"):
                continue  # 정의하는 쪽
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                kw = [k for k in node.keywords if k.arg == "batch"]
                if any(not (isinstance(k.value, ast.Constant) and k.value.value == "transaction") for k in kw) \
                        or (name in ("mask", "_mask_batch") and len(node.args) >= 3):
                    found.append(rel)
    return sorted(set(found))


def test_run_batch_is_used_only_by_dataset_builders():
    assert set(run_batch_uses([REPO_ROOT / "src", REPO_ROOT / "tools"], REPO_ROOT)) == RUN_ALLOWED


@pytest.mark.parametrize("src", ['masker.mask(raw, "strict_redaction", batch="run")',
                                 'masker.mask(raw, "strict_redaction", "run")',
                                 'B = "run"\nmasker.mask(raw, batch=B)'])
def test_planted_run_batch_outside_dataset_builders_is_caught(tmp_path, src):
    shutil.copytree(REPO_ROOT / "tools", tmp_path / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "tools" / "eval" / "planted.py").write_text(f"from tools.fixture_masker import masker\n{src}\n", encoding="utf-8")
    assert "tools/eval/planted.py" in run_batch_uses([tmp_path / "tools"], tmp_path)
