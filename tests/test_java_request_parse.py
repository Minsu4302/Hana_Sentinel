"""java_request_parse — Java 구문 파서 출력 = 명세 생성기의 기대 RawEnvelope((A) §2.9 구문 파서 규칙 v1.52, §2.10 표기 바이트).

오라클: 이 파일의 명세 생성기가 구조 명세(메서드·path·query 조각·헤더·본문 종류)에서 ① 원시 요청·응답 바이트와 ② 기대 RawEnvelope를
함께 만든다. 기대값은 원시 바이트를 파싱해서 얻지 않고 명세 요소에서 바로 계산한다(파서와 독립). 디코딩 정의(unquote_plus·
UTF-8 errors=replace)는 (A)가 정한 것을 Python 표준으로 그대로 쓴다. 입력은 실행 중 생성한 N5 더미이고 커밋하지 않는다.

함께 보는 것: 거부 사례의 내부 세부 종류(kind), 종단(파싱 → 마스킹 → §2.10 = 참조 마스커), 선택 규칙 표, meta 형식, 사유 코드 닫힌 목록,
설정 기본값 = Python 서버 기본값. 변이 확인은 Java 소스 복사본을 javac로 컴파일해 실행하고, 변이본 클래스가 로드됐는지 먼저 확인한다.
"""
from __future__ import annotations

import base64
import gzip
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote_plus

import pytest

from sentinel import canonical_json, sanitization_policy
from sentinel.pipeline import llm_adapter
from sentinel.server import config as server_config
from tests import test_java_masker_parity as parity
from tools import java_boundary as jb
from tools.fixture_masker import masker
from tools.fixture_masker.raw import RawEnvelope
from tools.mutation_guard import MutationNotApplied, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "burp-extension"
HARNESS = "sentinel.burp.transport.masker.ParseHarness"
CORE = "sentinel/burp/capture/core"
SEED = 20261125
CRLF = b"\r\n"
META = ("3f2c9a7e-1b4d-4c8e-9f00-0a1b2c3d4e5f", "2026-11-25T01:02:03.000456Z", "ext-0a1b2c3d")


# ─────────────────────────────── 하네스 실행
def run_harness(lines: list[str], classpath: list[Path] | None = None, jvm: tuple = ()) -> list[str]:
    cp = os.pathsep.join(str(p) for p in (classpath or [*parity._build_classpath(), parity._gson_jar()]))
    r = subprocess.run([str(parity._java()), *jvm, "-cp", cp, HARNESS], input=("".join(x + "\n" for x in lines)).encode("ascii"),
                       capture_output=True, timeout=600)
    assert r.returncode == 0, f"하네스 비정상 종료({r.returncode})"
    out = r.stdout.decode("ascii").splitlines()
    assert len(out) == len(lines)
    return out


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _line(cmd: str, case: dict) -> str:
    return "\t".join([cmd, _b64(case["req"]), _b64(case["resp"]), case["host"], str(case["port"]),
                      "1" if case["secure"] else "0", *META])


# ─────────────────────────────── 명세 → (원시 바이트, 기대값)
def _strip_ows(b: bytes) -> bytes:
    return b.strip(b" \t")


def _header_bytes(headers: list[tuple[bytes, bytes]]) -> bytes:
    return b"".join(n + b":" + v + CRLF for n, v in headers)


def _expected_headers(headers: list[tuple[bytes, bytes]]) -> list[dict]:
    return [{"name": n.decode("ascii"), "value": _strip_ows(v).decode("utf-8", "replace")} for n, v in headers]


def _first(headers: list[dict], name: str) -> str | None:
    return next((h["value"] for h in headers if h["name"].lower() == name.lower()), None)


def _chunk(payload: bytes, rng: random.Random, ext: bool = False, trailer: bool = False) -> bytes:
    out, i = b"", 0
    while i < len(payload):
        n = rng.randint(1, max(1, len(payload) - i))
        out += f"{n:x}".encode() + (b";ext=1" if ext else b"") + CRLF + payload[i:i + n] + CRLF
        i += n
    return out + b"0" + CRLF + (b"X-Trailer: dummy" + CRLF if trailer else b"") + CRLF


def _expected_body(headers: list[dict], payload: bytes | None) -> dict:
    """payload = 디청크 뒤 바이트(None = omitted). 엄격 UTF-8이면 utf8, 아니면 base64."""
    ct = _first(headers, "Content-Type")
    ctype = "" if ct is None else ct
    if payload is None:
        return {"content_type": ctype, "encoding": "omitted", "content": None}
    try:
        return {"content_type": ctype, "encoding": "utf8", "content": payload.decode("utf-8", "strict")}
    except UnicodeDecodeError:
        return {"content_type": ctype, "encoding": "base64", "content": base64.b64encode(payload).decode("ascii")}


def _pairs(text: str, location: str) -> list[dict]:
    out = []
    for piece in text.split("&"):
        if not piece:
            continue
        name, sep, value = piece.partition("=")
        out.append({"name": unquote_plus(name), "value": unquote_plus(value) if sep else "", "location": location})
    return out


def _media(ct: str) -> str:
    return ct.split(";", 1)[0].strip().lower()


def build(method: bytes, target: bytes, req_headers: list[tuple[bytes, bytes]], req_body: bytes, req_payload: bytes | None,
          resp_line: bytes, resp_headers: list[tuple[bytes, bytes]], resp_body: bytes, resp_payload: bytes | None,
          host: str = "juice-shop.local", port: int = 3000, secure: bool = False, version: bytes = b"HTTP/1.1") -> dict:
    """원시 바이트와 기대 RawEnvelope(§2.10 바이트). req_payload/resp_payload = 기대 본문 바이트(디청크 뒤, None = omitted)."""
    req = method + b" " + target + b" " + version + CRLF + _header_bytes(req_headers) + CRLF + req_body
    resp = resp_line + CRLF + _header_bytes(resp_headers) + CRLF + resp_body
    target_text = target.decode("utf-8", "replace")
    path, sep, query = target_text.partition("?")
    rq_headers = _expected_headers(req_headers)
    rq_body = _expected_body(rq_headers, req_payload)
    params = _pairs(query, "query") if sep else []
    if rq_body["encoding"] == "utf8" and _media(rq_body["content_type"]) == "application/x-www-form-urlencoded":
        params += _pairs(rq_body["content"], "form")
    rs_headers = _expected_headers(resp_headers)
    status = int(resp_line.split(b" ")[1])
    env = {"schema_version": "1.0", "transactions": [{
        "meta": {"transaction_id": META[0], "captured_at": META[1], "origin_ref": META[2]},
        "request": {"method": method.decode("ascii"), "scheme": "https" if secure else "http", "host": host, "port": port,
                    "path": path, "query_params": params, "headers": rq_headers, "body": rq_body},
        "response": {"status": status, "headers": rs_headers, "body": _expected_body(rs_headers, resp_payload),
                     "elapsed_ms": None}}]}
    return {"req": req, "resp": resp, "host": host, "port": port, "secure": secure,
            "expect": ("OK", canonical_json.dumps(env)), "raw_env": env}


def refuse(req: bytes, resp: bytes, kind: str) -> dict:
    return {"req": req, "resp": resp, "host": "juice-shop.local", "port": 3000, "secure": False, "expect": ("REFUSE", kind)}


# ─────────────────────────────── 무작위 코퍼스(N5 더미)
WORDS = ["apple juice", "dummy", "검색", "<svg>", "x' OR '1'='1", "a+b", "100%", "\U0001f600", "q&a", "k=v", ""]
HEADER_NAMES = [b"Accept", b"User-Agent", b"X-Request-Id", b"Cookie", b"Authorization", b"X-Api-Key", b"x-custom", b"X-CUSTOM",
                b"Accept-Language", b"X-Note"]


def _piece(rng: random.Random) -> str:
    name, value = rng.choice(["q", "id", "password", "token", "비밀", "x"]), rng.choice(WORDS) + rng.choice(["", "dummy1"])
    return rng.choice([f"{quote_plus(name)}={quote_plus(value)}", f"{quote(name)}={quote(value)}", f"{name}={value}".replace("&", "").replace(" ", "+"),
                       quote_plus(name), f"{quote_plus(name)}=", "%zz=%e0%80", "a=1+2"])


def _value(rng: random.Random) -> bytes:
    core = rng.choice([b"dummy-" + str(rng.randint(1, 999)).encode(), "값 dummy".encode(), b"a\xffb", b"text/html; q=0.9",
                       b"sid=dummyCookie123; theme=dark", b"Bearer dummyTokenAbc123"])
    return rng.choice([b"", b" ", b"\t", b"  "]) + core + rng.choice([b"", b" ", b"\t "])


def _body(rng: random.Random, request: bool) -> tuple[list[tuple[bytes, bytes]], bytes, bytes | None]:
    kind = rng.choice(["none", "json", "form", "binary", "chunked", "gzip"] if request else
                      ["none", "json", "text", "binary", "chunked", "gzip"])
    if kind == "none":
        return [], b"", b""
    if kind == "json":
        payload = json.dumps({"password": "dummyPw" + str(rng.randint(1, 99)), "note": rng.choice(WORDS)},
                             ensure_ascii=rng.random() < 0.5).encode("utf-8")
        return [(b"Content-Type", rng.choice([b"application/json", b" application/json; charset=utf-8 "]))], payload, payload
    if kind == "form":
        payload = "&".join(_piece(rng) for _ in range(rng.randint(1, 4))).encode("utf-8")
        return [(b"Content-Type", rng.choice([b"application/x-www-form-urlencoded",
                                              b"Application/X-WWW-Form-Urlencoded; charset=UTF-8"]))], payload, payload
    if kind == "text":
        payload = (" ".join(rng.choice(WORDS) for _ in range(5))).encode("utf-8")
        return [(b"Content-Type", b"text/html; charset=utf-8")], payload, payload
    if kind == "binary":
        payload = bytes([0x89, 0x50, 0x4E, 0x47, 0xFF, 0x00, rng.randint(0, 255)])
        return [(b"Content-Type", b"image/png")], payload, payload
    if kind == "chunked":
        payload = ("chunked " + rng.choice(WORDS) * 3).encode("utf-8")
        return ([(b"Content-Type", b"text/plain"), (b"Transfer-Encoding", rng.choice([b"chunked", b" Chunked "]))],
                _chunk(payload, rng, ext=rng.random() < 0.3, trailer=rng.random() < 0.3), payload)
    payload = gzip.compress(b"dummy compressed body " * 4, mtime=0)
    return [(b"Content-Type", b"text/plain"), (b"Content-Encoding", b"gzip")], payload, payload


def seeded_cases(n: int = 120) -> dict[str, dict]:
    rng = random.Random(SEED)
    cases = {}
    for i in range(n):
        segs = [rng.choice(["rest", "api", "%2Fx", "검색", "a%20b", "items", "1"]) for _ in range(rng.randint(1, 3))]
        path = "/" + "/".join(segs)
        pieces = [_piece(rng) for _ in range(rng.randint(0, 4))]
        if rng.random() < 0.2:
            pieces.insert(rng.randint(0, len(pieces)), "")
        target = (path + ("?" + "&".join(pieces) if pieces or rng.random() < 0.2 else "")).encode("utf-8")
        rq_extra, rq_raw, rq_payload = _body(rng, True)
        rs_extra, rs_raw, rs_payload = _body(rng, False)
        rq_headers = [(rng.choice(HEADER_NAMES), _value(rng)) for _ in range(rng.randint(0, 5))] + rq_extra
        rs_headers = [(rng.choice(HEADER_NAMES), _value(rng)) for _ in range(rng.randint(0, 3))] + rs_extra
        rng.shuffle(rq_headers)
        status = rng.choice([200, 201, 302, 404, 500])
        resp_line = rng.choice([f"HTTP/1.1 {status} OK", f"HTTP/1.1 {status}", f"HTTP/2 {status}", f"HTTP/1.1 {status} Not Very Found"])
        cases[f"seed{i:03d}"] = build(rng.choice([b"GET", b"POST", b"PUT", b"DELETE", b"PATCH"]), target, rq_headers, rq_raw,
                                      rq_payload, resp_line.encode(), rs_headers, rs_raw, rs_payload,
                                      host=rng.choice(["juice-shop.local", "dummy-api.local"]), port=rng.choice([3000, 443, 8080]),
                                      secure=rng.random() < 0.5, version=rng.choice([b"HTTP/1.1", b"HTTP/2"]))
    return cases


OK_RESP = b"HTTP/1.1 200 OK" + CRLF + b"Content-Type: text/plain" + CRLF + CRLF + b"ok-body"


def adversarial() -> dict[str, dict]:
    rng = random.Random(SEED + 1)
    R = lambda **kw: build(**{"method": b"GET", "target": b"/a", "req_headers": [], "req_body": b"", "req_payload": b"",  # noqa: E731
                              "resp_line": b"HTTP/1.1 200 OK", "resp_headers": [], "resp_body": b"", "resp_payload": b"", **kw})
    c = {}
    c["duplicate_and_case_headers"] = R(req_headers=[(b"X-Dup", b"1"), (b"x-dup", b"2"), (b"X-DUP", b" 3 ")])
    c["ows_tabs"] = R(req_headers=[(b"X-Ows", b"\t \tdummy value\t ")])
    c["non_ascii_header_value"] = R(req_headers=[(b"X-Note", "값 \U0001f600".encode())])
    c["invalid_utf8_header_value"] = R(req_headers=[(b"X-Note", b"a\xff\xfeb\xed\xa0\x80c")])
    pay = b"chunked dummy payload \xec\x95\x88\xeb\x85\x95"
    c["chunked_ok"] = R(resp_headers=[(b"Transfer-Encoding", b"chunked")], resp_body=_chunk(pay, rng, ext=True, trailer=True),
                        resp_payload=pay)
    c["chunked_bad_size"] = R(resp_headers=[(b"Transfer-Encoding", b"chunked")], resp_body=b"zz" + CRLF + b"x" + CRLF + b"0" + CRLF + CRLF,
                              resp_payload=None)
    c["chunked_trailing_garbage"] = R(resp_headers=[(b"Transfer-Encoding", b"chunked")],
                                      resp_body=b"3" + CRLF + b"abc" + CRLF + b"0" + CRLF + CRLF + b"extra", resp_payload=None)
    c["chunked_short_data"] = R(resp_headers=[(b"Transfer-Encoding", b"chunked")], resp_body=b"9" + CRLF + b"abc" + CRLF,
                                resp_payload=None)
    c["chunked_no_final_crlf"] = R(resp_headers=[(b"Transfer-Encoding", b"chunked")], resp_body=b"3" + CRLF + b"abc" + CRLF + b"0" + CRLF,
                                   resp_payload=None)
    c["transfer_encoding_gzip"] = R(resp_headers=[(b"Transfer-Encoding", b"gzip")], resp_body=b"dummy", resp_payload=None)
    gz = gzip.compress(b"dummy", mtime=0)
    c["content_encoding_gzip"] = R(resp_headers=[(b"Content-Encoding", b"gzip")], resp_body=gz, resp_payload=gz)
    c["invalid_utf8_body"] = R(resp_body=b"ab\xc0\xafcd", resp_payload=b"ab\xc0\xafcd")
    c["no_content_type"] = R(req_body=b"plain dummy", req_payload=b"plain dummy", method=b"POST")
    c["first_content_type_wins"] = R(resp_headers=[(b"Content-Type", b"text/plain"), (b"Content-Type", b"application/json")],
                                     resp_body=b"{}", resp_payload=b"{}")
    c["form_with_charset"] = R(method=b"POST", req_headers=[(b"Content-Type", b"application/x-www-form-urlencoded; charset=utf-8")],
                               req_body=b"user=dummy&pass+word=a%2Bb&&k", req_payload=b"user=dummy&pass+word=a%2Bb&&k")
    c["form_invalid_utf8_no_params"] = R(method=b"POST", req_headers=[(b"Content-Type", b"application/x-www-form-urlencoded")],
                                         req_body=b"a=\xff", req_payload=b"a=\xff")
    c["plus_and_bad_percent"] = R(target=b"/s?q=a+b&r=%zz&s=%e0%80&t=%E2%82%AC")
    c["empty_query"] = R(target=b"/s?")
    c["double_amp_and_key_only"] = R(target=b"/s?a=1&&b&c=")
    c["percent_kept_in_path"] = R(target=b"/a%2Fb/%3F/\xea\xb2\x80\xec\x83\x89/\xff")
    c["http2_version"] = R(version=b"HTTP/2", resp_line=b"HTTP/2 200")
    c["status_without_reason"] = R(resp_line=b"HTTP/1.1 404")
    c["empty_request_body_get"] = R()
    # 거부(내부 세부 종류)
    base = b"GET /a HTTP/1.1" + CRLF + b"Host: x" + CRLF
    c["obs_fold"] = refuse(base + b"X-Long: a" + CRLF + b"\tcontinued: b" + CRLF + CRLF, OK_RESP, "obs_fold")
    c["obs_fold_space"] = refuse(base + b"X-Long: a" + CRLF + b" more" + CRLF + CRLF, OK_RESP, "obs_fold")
    c["absolute_form"] = refuse(b"GET http://juice-shop.local/a HTTP/1.1" + CRLF + CRLF, OK_RESP, "target_form")
    c["asterisk_form"] = refuse(b"OPTIONS * HTTP/1.1" + CRLF + CRLF, OK_RESP, "target_form")
    c["fragment_in_target"] = refuse(b"GET /a#x HTTP/1.1" + CRLF + CRLF, OK_RESP, "target_form")
    c["bare_lf"] = refuse(b"GET /a HTTP/1.1\nHost: x\r\n\r\n", OK_RESP, "line_ending")
    c["no_header_end"] = refuse(b"GET /a HTTP/1.1" + CRLF + b"Host: x" + CRLF, OK_RESP, "no_header_end")
    c["header_without_colon"] = refuse(base + b"NoColon" + CRLF + CRLF, OK_RESP, "header_syntax")
    c["space_before_colon"] = refuse(base + b"X-Bad : v" + CRLF + CRLF, OK_RESP, "header_syntax")
    c["bad_method"] = refuse(b"G(T /a HTTP/1.1" + CRLF + CRLF, OK_RESP, "request_line")
    c["bad_version"] = refuse(b"GET /a HTTP/1.1x" + CRLF + CRLF, OK_RESP, "request_line")
    c["two_spaces"] = refuse(b"GET  /a HTTP/1.1" + CRLF + CRLF, OK_RESP, "request_line")
    ok_req = b"GET /a HTTP/1.1" + CRLF + CRLF
    c["status_99"] = refuse(ok_req, b"HTTP/1.1 099 X" + CRLF + CRLF, "status_line")
    c["status_600"] = refuse(ok_req, b"HTTP/1.1 600 X" + CRLF + CRLF, "status_line")
    c["status_letters"] = refuse(ok_req, b"HTTP/1.1 2OO OK" + CRLF + CRLF, "status_line")
    c["empty_response"] = refuse(ok_req, b"", "no_header_end")
    return c


@pytest.fixture(scope="module")
def cases() -> dict[str, dict]:
    return {**seeded_cases(), **adversarial()}


@pytest.fixture(scope="module")
def parsed(cases) -> dict[str, tuple]:
    out = run_harness([_line("PARSE", c) for c in cases.values()])
    return {k: tuple(line.split("\t", 1)) for k, line in zip(cases, out)}


def _decode(result: tuple) -> tuple:
    return (result[0], base64.b64decode(result[1])) if result[0] == "OK" else result


# ─────────────────────────────── 파서 = 오라클
def test_java_parser_output_equals_oracle_bytes(cases, parsed):
    diffs = []
    for name, case in cases.items():
        got = _decode(parsed[name])
        if got != case["expect"]:
            where = "-"
            if got[0] == "OK" == case["expect"][0]:
                where = " ".join(parity._first_diff(json.loads(got[1]), json.loads(case["expect"][1])) or ("bytes",))
            diffs.append(f"{name}: java={got[0]} oracle={case['expect'][0]} {where}")  # 값 없음 — 종류·경로만
    assert diffs == [], "\n".join(diffs[:40])


def test_corpus_reaches_every_parser_rule(cases):
    oks = [json.loads(c["expect"][1])["transactions"][0] for c in cases.values() if c["expect"][0] == "OK"]
    bodies = [tx[s]["body"] for tx in oks for s in ("request", "response")]
    assert {b["encoding"] for b in bodies} == {"utf8", "base64", "omitted"}
    params = [p for tx in oks for p in tx["request"]["query_params"]]
    assert {p["location"] for p in params} == {"query", "form"}
    assert any("\ufffd" in h["value"] for tx in oks for h in tx["request"]["headers"])
    kinds = {c["expect"][1] for c in cases.values() if c["expect"][0] == "REFUSE"}
    assert kinds == {"obs_fold", "target_form", "line_ending", "no_header_end", "header_syntax", "request_line", "status_line"}
    assert sum(1 for k in cases if k.startswith("seed")) == 120


# ─────────────────────────────── 종단: 파싱 → 마스킹 → §2.10 = 참조 마스커(base64 본문은 동등성 범위 밖이라 제외)
def test_parse_then_mask_equals_reference_masker(cases):
    names = [k for k, c in cases.items() if c["expect"][0] == "OK"
             and all(c["raw_env"]["transactions"][0][s]["body"]["encoding"] != "base64" for s in ("request", "response"))]
    out = run_harness([_line("PREPARE", cases[k]) for k in names])
    diffs = []
    for name, line in zip(names, out):
        raw = RawEnvelope.model_validate_json(json.dumps(cases[name]["raw_env"]))
        try:
            ref = ("OK", masker.mask(raw, "strict_redaction")[0][1])
        except masker.MaskerRejected:
            ref = ("REFUSE", "mask_refused")
        got = _decode(tuple(line.split("\t", 1)))
        if got != ref:
            diffs.append(f"{name}: java={got[0]} ref={ref[0]}")
    assert len(names) >= 60 and diffs == [], "\n".join(diffs[:40])


# ─────────────────────────────── 선택 규칙·meta·사유 코드·설정 기본값
def _expected_selection(origin: str, repeater: bool, count: int, has_response: bool) -> str:
    if repeater:
        return "repeater_source"
    if origin == "EDITOR":
        return "editable_message"
    if count != 1:
        return "selection_not_single"
    return "-" if has_response else "no_response"


SELECTION_TABLE = list(itertools.product(["LIST", "VIEWER", "EDITOR"], [False, True], [0, 1, 2], [False, True]))


def test_selection_rule_table():
    out = run_harness([f"SELECT\t{o}\t{int(r)}\t{n}\t{int(h)}" for o, r, n, h in SELECTION_TABLE])
    got = [line.split("\t")[1] for line in out]
    assert got == [_expected_selection(*row) for row in SELECTION_TABLE]


def test_meta_format():
    out = run_harness(["META"] * 40)
    before = datetime.now(timezone.utc)
    seen = set()
    for line in out:
        _, tid, captured, ref = line.split("\t")
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", tid)
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?Z", captured)
        assert not captured.endswith(".000000Z")
        assert abs((datetime.fromisoformat(captured.replace("Z", "+00:00")) - before).total_seconds()) < 120
        assert re.fullmatch(r"ext-[0-9a-f]{8}", ref)
        seen.add((tid, ref))
    assert len(seen) == 40


def _reason_codes() -> list[str]:
    text = (PROJECT / "src/main/java" / CORE / "Reasons.java").read_text(encoding="utf-8")
    consts = dict(re.findall(r'public static final String (\w+) = "([a-z_]+)";', text))
    start = text.index("ALL = List.of(") + len("ALL = List.of(")
    block = text[start:text.index(");", start)]
    names = re.findall(r"\b([A-Z_]+)\b", block)
    assert sorted(names) == sorted(consts), "ALL과 상수 목록이 다름"
    return [consts[n] for n in names]


def test_reason_codes_are_a_closed_list_disjoint_from_forbidden_tokens():
    codes = _reason_codes()
    forbidden = {t for v in jb.forbidden_tokens().values() for t in v}
    assert set(codes) & forbidden == set()
    design = (REPO_ROOT / "docs/design-decision.md").read_text(encoding="utf-8")
    draft = design[design.index("사유 코드(v1.52)"):]
    draft = draft[:draft.index("\n")]
    assert set(re.findall(r"`([a-z_]+)`", draft)) <= set(codes), "(A) 초안 목록의 코드가 Java 목록에 없음"


def test_settings_defaults_equal_python_server_defaults():
    text = (PROJECT / "src/main/java/sentinel/burp/transport/Settings.java").read_text(encoding="utf-8")
    val = lambda name: int(re.search(rf"{name} = (\d+);", text).group(1))  # noqa: E731
    assert val("DEFAULT_PORT") == server_config.DEFAULT_PORT
    assert val("DEFAULT_QUEUE_LIMIT") == server_config.DEFAULT_QUEUE_LIMIT
    assert val("DEFAULT_DEADLINE_SECONDS") == int(llm_adapter.DEFAULT_LIMITS.deadline_seconds)
    worker = (PROJECT / "src/main/java/sentinel/burp/transport/Worker.java").read_text(encoding="utf-8")
    assert "CONCURRENCY = 1;" in worker and "QUEUE = 2;" in worker


# ─────────────────────────────── 변이 확인(Java — 변이본 로드 표지 확인 후 결과 해석)
def compile_without_montoya(tmp: Path, rel: str, old: str, new: str) -> tuple[Path, Path]:
    """Montoya를 쓰지 않는 소스(main·test)만 복사본에서 javac로 컴파일. 변이는 rel 파일 한 곳."""
    mutant = copy_with_mutation(PROJECT, ["src"], tmp / "mut", rel, old, new)
    sources = [str(p) for p in (tmp / "mut" / "src").rglob("*.java") if "burp.api" not in p.read_text(encoding="utf-8")]
    out = tmp / "classes"
    r = subprocess.run([str(parity._java("javac")), "--release", "17", "-encoding", "UTF-8", "-nowarn", "-cp",
                        str(parity._gson_jar()), "-d", str(out), *sources], capture_output=True, timeout=600)
    assert r.returncode == 0, "변이본 컴파일 실패"
    res = out / "sentinel/burp/transport/masker"
    res.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sanitization_policy.POLICY_PATH, res / "sanitization_policy.json")
    return out, mutant


def _assert_loaded(log: Path, class_name: str, class_dir: Path) -> None:
    text = log.read_text(encoding="utf-8", errors="replace")
    m = re.search(re.escape(class_name) + r" source: file:/?(\S+)", text)
    if not m or parity._norm(m.group(1)) != parity._norm(str(class_dir)):
        raise MutationNotApplied(f"{class_name}가 변이본 폴더에서 로드되지 않음")


JAVA_MUTATIONS = {
    "selection_single_check_removed": (f"src/main/java/{CORE}/Selection.java", "if (count != 1) {", "if (false) {",
                                       "sentinel.burp.capture.core.Selection", "select"),
    "repeater_check_removed": (f"src/main/java/{CORE}/Selection.java", "if (fromRepeater) {", "if (false) {",
                               "sentinel.burp.capture.core.Selection", "select"),
    "obs_fold_refusal_removed": (f"src/main/java/{CORE}/RawParser.java",
                                 "if (l.length > 0 && (l[0] == ' ' || l[0] == '\\t')) {", "if (false) {",
                                 "sentinel.burp.capture.core.RawParser", "parse"),
    "chunked_strict_end_removed": (f"src/main/java/{CORE}/RawParser.java",
                                   "return i == b.length ? out.toByteArray() : null;", "return out.toByteArray();",
                                   "sentinel.burp.capture.core.RawParser", "parse"),
}


@pytest.mark.parametrize("name", sorted(JAVA_MUTATIONS))
def test_parser_and_selection_are_load_bearing_under_verified_java_mutation(tmp_path, cases, name):
    rel, old, new, loaded_class, what = JAVA_MUTATIONS[name]
    classes, _ = compile_without_montoya(tmp_path, rel, old, new)
    log = tmp_path / "load.log"
    cp = [classes, parity._gson_jar()]
    if what == "select":
        out = run_harness([f"SELECT\t{o}\t{int(r)}\t{n}\t{int(h)}" for o, r, n, h in SELECTION_TABLE], cp, (parity._xlog(log),))
        _assert_loaded(log, loaded_class, classes)
        assert [line.split("\t")[1] for line in out] != [_expected_selection(*row) for row in SELECTION_TABLE], f"변이 {name} 생존"
    else:
        out = run_harness([_line("PARSE", c) for c in cases.values()], cp, (parity._xlog(log),))
        _assert_loaded(log, loaded_class, classes)
        assert any(_decode(tuple(line.split("\t", 1))) != c["expect"] for line, c in zip(out, cases.values())), f"변이 {name} 생존"


def test_unmutated_copy_compiled_the_same_way_passes_as_control(tmp_path, cases):
    classes, _ = compile_without_montoya(tmp_path, f"src/main/java/{CORE}/Selection.java", "public final class Selection {",
                                         "public final class Selection  {")
    log = tmp_path / "load.log"
    out = run_harness([_line("PARSE", c) for c in cases.values()], [classes, parity._gson_jar()], (parity._xlog(log),))
    _assert_loaded(log, "sentinel.burp.capture.core.RawParser", classes)
    assert [_decode(tuple(line.split("\t", 1))) for line in out] == [c["expect"] for c in cases.values()]
