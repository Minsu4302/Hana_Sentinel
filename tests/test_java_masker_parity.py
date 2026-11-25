"""java_masker_parity — Java 마스커 코어 출력 = 참조 마스커(fixture 마스커) 출력, (A) §2.10 바이트 일치((A) §2.9·§3.3).

방법:
- Java 쪽은 make verify의 Java 단계가 만든 오프라인 빌드 산출물(build/classes·build/resources)을 `java -cp`로 실행한다.
  클래스패스에는 gson jar 하나만 더한다 — GRADLE_USER_HOME 캐시에서 찾고, sha256이 verification-metadata의 고정값과
  같을 때만 쓴다. error_prone_annotations는 넣지 않는다(런타임 불필요를 매번 다시 확인).
- 입력은 실행 중에 만든 N5 더미 RawEnvelope다(고정 시드 코퍼스 + 적대 사례). 디스크에는 테스트 임시 폴더만 쓴다
  (참조 마스커의 load_raw가 레포 밖 파일 경로를 받으므로). 원본 파일은 커밋하지 않는다.
- 비교는 사례마다 결과 종류(OK / REJECT 사유 코드)와 Envelope 바이트. 불일치 보고에는 값 없이 사례 id·JSON 경로·종류만 쓴다.
- base64는 범위 밖이다(Java는 항상 omitted, 참조 마스커는 정책 패턴으로 판정). Java가 항상 omitted로 내는지는 따로 본다.
- 변이 확인: Java 소스를 임시 폴더에 복사해 한 곳을 바꾸고 javac로 컴파일해 실행한다. 결과를 읽기 전에 변이본 클래스가
  실제로 로드됐는지(-Xlog:class+load의 출처 경로)를 먼저 확인한다.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sentinel import sanitization_policy
from sentinel.common_types import FILLER, TRUNCATION_MARK
from tools import java_build
from tools.fixture_masker import masker
from tools.mutation_guard import MutationNotApplied, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "burp-extension"
BUILD = PROJECT / "build"
MAIN_CLASS = "sentinel.burp.transport.masker.ParityHarness"
CORE_PKG = "sentinel/burp/transport/masker"
GSON = ("com.google.code.gson", "gson", "2.15.0")
SEED = 20261124


# ─────────────────────────────── Java 실행 환경
def _metadata_sha256(group: str, name: str, file: str) -> str:
    ns = {"g": "https://schema.gradle.org/dependency-verification"}
    root = ET.fromstring((PROJECT / "gradle" / "verification-metadata.xml").read_text(encoding="utf-8"))
    for c in root.findall("g:components/g:component", ns):
        if (c.get("group"), c.get("name")) == (group, name):
            for a in c.findall("g:artifact", ns):
                if a.get("name") == file:
                    return a.find("g:sha256", ns).get("value")
    raise AssertionError(f"verification-metadata에 {group}:{name} {file} 없음")


def _gson_jar() -> Path:
    home = os.environ.get("GRADLE_USER_HOME")
    assert home, "GRADLE_USER_HOME 없음 — 동등성은 오프라인 빌드 산출물과 의존성 캐시가 필요하다(건너뛰지 않는다)"
    g, a, v = GSON
    want = _metadata_sha256(g, a, f"{a}-{v}.jar")
    found = list((Path(home) / "caches" / "modules-2" / "files-2.1" / g / a / v).glob(f"*/{a}-{v}.jar"))
    good = [p for p in found if hashlib.sha256(p.read_bytes()).hexdigest() == want]
    assert len(good) == 1, f"해시가 고정값과 같은 gson jar가 정확히 1개여야 함(후보 {len(found)}개)"
    return good[0]


def _java(tool: str = "java") -> Path:
    home = os.environ.get("JAVA_HOME")
    assert home, "JAVA_HOME 없음 — JDK 21이 필요하다(건너뛰지 않는다)"
    for name in (f"{tool}.exe", tool):
        p = Path(home) / "bin" / name
        if p.is_file():
            return p
    raise AssertionError(f"JAVA_HOME에 {tool}가 없음")


def _build_classpath() -> list[Path]:
    dirs = [BUILD / "classes" / "java" / "main", BUILD / "resources" / "main", BUILD / "classes" / "java" / "test"]
    for d in dirs:
        assert d.is_dir(), f"빌드 산출물 없음: {d.relative_to(REPO_ROOT)} — make verify의 Java 단계가 먼저 돌아야 한다"
    assert (dirs[2] / CORE_PKG / "ParityHarness.class").is_file()
    assert not java_build.stale_build(PROJECT), ("빌드 산출물이 현재 소스로 만든 것이 아님(build/source-digest.txt 불일치) — "
                                                 "make verify의 Java 단계를 먼저 돌린다")
    return dirs


def run_java(cases: list[tuple[str, int, bytes]], policies: list[Path] = (), classpath: list[Path] | None = None,
             jvm: list[str] = ()) -> list[str]:
    cp = os.pathsep.join(str(p) for p in (classpath or [*_build_classpath(), _gson_jar()]))
    lines = "".join(f"{mode}\t{idx}\t{base64.b64encode(raw).decode('ascii')}\n" for mode, idx, raw in cases)
    r = subprocess.run([str(_java()), *jvm, "-cp", cp, MAIN_CLASS, *map(str, policies)], input=lines.encode("ascii"),
                       capture_output=True, timeout=600)
    assert r.returncode == 0, f"하네스 비정상 종료({r.returncode}) stderr 줄 수={len(r.stderr.splitlines())}"
    out = r.stdout.decode("ascii").splitlines()
    assert len(out) == len(cases), (len(out), len(cases))
    return out


def _parse_java(line: str) -> tuple:
    f = line.split("\t")
    if f[0] == "OK":
        return ("OK", [(f[i], base64.b64decode(f[i + 1])) for i in range(1, len(f), 2)])
    if f[0] == "REJECT":
        return ("REJECT", f[1])
    return (f[0],)


# ─────────────────────────────── 참조 마스커
def _reference(raw: bytes, mode: str, policy, work: Path, n: int) -> tuple:
    path = work / f"raw-{n}.json"
    path.write_bytes(raw)
    saved = masker.POLICY
    masker.POLICY = policy
    try:
        return ("OK", masker.mask(masker.load_raw(path), mode))
    except masker.MaskerRejected as e:
        return ("REJECT", e.code)
    finally:
        masker.POLICY = saved
        path.unlink()


# ─────────────────────────────── 불일치 보고(값 없음)
def _first_diff(a, b, path: str = "") -> tuple[str, str]:
    if type(a) is not type(b):
        return path or "/", "type"
    if isinstance(a, dict):
        if list(a) != list(b):
            return path or "/", "keys_or_order"
        for k in a:
            d = _first_diff(a[k], b[k], f"{path}/{k}")
            if d:
                return d
        return ()
    if isinstance(a, list):
        if len(a) != len(b):
            return path or "/", "length"
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_diff(x, y, f"{path}/{i}")
            if d:
                return d
        return ()
    return (path or "/", "value") if a != b else ()


def compare(case_ids: list[str], java: list[tuple], ref: list[tuple]) -> list[str]:
    """불일치 목록 — 사례 id·JSON 경로·종류만(값·원문 없음)."""
    out = []
    for cid, j, r in zip(case_ids, java, ref):
        if j[0] != r[0]:
            out.append(f"{cid}: 결과 종류 java={j[0]} ref={r[0]}")
        elif j[0] == "REJECT" and j[1] != r[1]:
            out.append(f"{cid}: 사유 코드 java={j[1]} ref={r[1]}")
        elif j[0] == "OK":
            if [n for n, _ in j[1]] != [n for n, _ in r[1]]:
                out.append(f"{cid}: 출력 개수·이름")
                continue
            for k, ((_, jb), (_, rb)) in enumerate(zip(j[1], r[1])):
                if jb != rb:
                    try:
                        where, kind = _first_diff(json.loads(jb), json.loads(rb)) or ("/", "bytes_only")
                    except ValueError:
                        where, kind = "/", "not_json"
                    out.append(f"{cid}#{k}: {where} {kind}")
    return out


# ─────────────────────────────── 코퍼스(N5 더미 — 실행 중 생성)
HEADER_NAMES = ["Host", "Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token", "X-Session-Id",
                "X-Client-Secret", "Content-Type", "Accept", "User-Agent", "X-Request-Id", "AUTHORIZATION", "cOOkie",
                "x-APIKEY-hint", "X-Tökén", "X-\u0130Token", "X-세션"]
JSON_KEYS = ["user", "password", "Password", "PASSWD", "access_token", "refreshToken", "id", "name", "items", "nested",
             "pwd", "note", "csrf_token", "data", "client_secret", "비밀", "a/b", "t~k"]
FORM_NAMES = ["user", "password", "PassWord", "ACCESS_TOKEN", "token", "q", "%70assword", "pass+word", "id_token",
              "csrf", "note", "비밀"]
CONTENT_TYPES = {
    "json": ["application/json", "application/json; charset=utf-8", "application/vnd.api+json", " Application/JSON "],
    "form": ["application/x-www-form-urlencoded", " Application/X-WWW-Form-Urlencoded ; charset=UTF-8"],
    "text": ["text/plain", "text/html; charset=utf-8"],
}
ODD = ["é", "가", "\U0001f600", "\u2028", "\x01", "\t", "\n", "\x08", "\x0c", "\x7f", "\"", "\\", "/",
       "\u00a0", "\u3000", "\ufffd", "%", "+", "&", "="]


def _tok(rng: random.Random, n: int = 12, odd: bool = False) -> str:
    s = "dummy" + "".join(rng.choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(n))
    if odd and rng.random() < 0.5:
        i = rng.randrange(len(s))
        s = s[:i] + rng.choice(ODD) + s[i:]
    return s


_GLOBS = masker._body_globs()


def _secret_slot(kind: str, name: str | None) -> bool:
    """정본 정책으로 마스킹되는 자리인가 — 공유 값 풀(관계 보존 모드의 반복)은 이런 자리에만 쓴다.
    마스킹되지 않는 자리에 같은 값을 두면 유출 검사가 그 사례를 통째로 거부해 비교가 얇아진다."""
    if name is None:
        return False
    if kind == "header":
        return sanitization_policy.DEFAULT_POLICY.requires_masked_header(name)
    if kind == "form":
        return masker._matches(masker.unquote_plus(name), _GLOBS["form"])
    return masker._matches(name, _GLOBS["json"])


def _value(rng: random.Random, pool: list[str], kind: str, name: str | None, odd: bool = True) -> str:
    if pool and _secret_slot(kind, name) and rng.random() < 0.5:
        return rng.choice(pool)
    return _tok(rng, odd=odd)


def _json_value(rng: random.Random, pool: list[str], depth: int = 0, key: str | None = None):
    r = rng.random()
    if depth < 3 and r < 0.25:
        keys = [rng.choice(JSON_KEYS) for _ in range(rng.randint(0, 4))]
        return {k: _json_value(rng, pool, depth + 1, k) for k in keys}
    if depth < 3 and r < 0.35:
        return [_json_value(rng, pool, depth + 1) for _ in range(rng.randint(0, 3))]
    if r < 0.45:
        return rng.choice([0, -7, 12345, True, False, None])
    return _value(rng, pool, "json", key)


def _body(rng: random.Random, pool: list[str]) -> dict:
    kind = rng.choice(["json", "json", "form", "form", "text", "empty", "none", "omitted"])
    if kind == "json":
        keys = [rng.choice(JSON_KEYS) for _ in range(rng.randint(1, 5))]
        doc = {k: _json_value(rng, pool, 0, k) for k in keys}
        sep = rng.choice([(",", ":"), (", ", ": "), (",", ": ")])
        content = json.dumps(doc, ensure_ascii=rng.random() < 0.5, separators=sep, indent=rng.choice([None, None, 2]))
        return {"content_type": rng.choice(CONTENT_TYPES["json"]), "encoding": "utf8", "content": content}
    if kind == "form":
        pairs = []
        for _ in range(rng.randint(1, 5)):
            name = rng.choice(FORM_NAMES)
            value = _value(rng, pool, "form", name)
            pairs.append(rng.choice([f"{name}={value}", f"{name}=", name, f"{name}={value.replace(' ', '+')}"]))
        return {"content_type": rng.choice(CONTENT_TYPES["form"]), "encoding": "utf8", "content": "&".join(pairs)}
    if kind == "text":
        return {"content_type": rng.choice(CONTENT_TYPES["text"]), "encoding": "utf8",
                "content": " ".join(_tok(rng, odd=True) for _ in range(rng.randint(0, 6)))}
    if kind == "empty":
        return {"content_type": "text/plain", "encoding": "utf8", "content": ""}
    if kind == "none":
        return {"content_type": "application/json", "encoding": "utf8", "content": None}
    return {"content_type": "image/png", "encoding": "omitted", "content": None}


def _header_value(rng: random.Random, name: str, pool: list[str]) -> str:
    low = name.lower()
    secret = rng.choice(pool) if pool and _secret_slot("header", name) and rng.random() < 0.5 else _tok(rng, 16)
    if "cookie" in low:
        sp = rng.choice([" ", "\u00a0", "\u3000", ""])
        return f"sid={secret};{sp}theme=dark,{sp}pref={_tok(rng, 10)}"
    if "authorization" in low:
        return rng.choice([f"Bearer {secret}", f"Basic{rng.choice([' ', '  ', chr(0xA0)])}{secret}", secret])
    if low == "content-type":
        return "application/json"
    if low == "host":
        return "juice-shop.local:3000"
    return secret if rng.random() < 0.7 else _tok(rng, 6)


def _time(rng: random.Random) -> str:
    frac = rng.choice(["", ".5", ".000000", ".123456", ".0001"])
    zone = rng.choice(["Z", "+09:00", "-00:00", "+00:00", "-05:30"])
    return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:" \
           f"{rng.randint(0, 59):02d}{frac}{zone}"


def _tx(rng: random.Random, pool: list[str], req_body: dict | None = None, resp_body: dict | None = None,
        headers: list | None = None, params: list | None = None, path: str | None = None,
        resp_headers: list | None = None) -> dict:
    tid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    if headers is None:
        headers = [{"name": n, "value": _header_value(rng, n, pool)} for n in rng.sample(HEADER_NAMES, rng.randint(0, 6))]
    if params is None:
        params = []
        for _ in range(rng.randint(0, 3)):
            name, location = rng.choice(FORM_NAMES), rng.choice(["query", "form"])
            secret = location == "form" and masker._matches(name, _GLOBS["form"])
            value = rng.choice(pool) if pool and secret and rng.random() < 0.5 else _tok(rng)
            params.append({"name": name, "value": value, "location": location})
    return {
        "meta": {"transaction_id": tid.upper() if rng.random() < 0.2 else tid, "captured_at": _time(rng),
                 "origin_ref": f"burp-{rng.randrange(1 << 16):04x}"},
        "request": {"method": rng.choice(["GET", "POST", "PUT"]), "scheme": rng.choice(["http", "https"]),
                    "host": "juice-shop.local", "port": rng.choice([3000, 443, 8080]),
                    "path": path or f"/rest/{_tok(rng, 4)}/%3F{rng.randint(1, 99)}", "query_params": params,
                    "headers": headers, "body": req_body or _body(rng, pool)},
        "response": {"status": rng.choice([200, 201, 302, 404, 500]),
                     "headers": resp_headers if resp_headers is not None else
                     [{"name": n, "value": _header_value(rng, n, pool)} for n in rng.sample(HEADER_NAMES, rng.randint(0, 4))],
                     "body": resp_body or _body(rng, pool), "elapsed_ms": rng.choice([None, 0, 12, 3456])},
    }


def _raw(*txs: dict) -> bytes:
    return json.dumps({"schema_version": "1.0", "transactions": list(txs)}, ensure_ascii=False).encode("utf-8")


def _utf8(content: str, ct: str = "text/plain") -> dict:
    return {"content_type": ct, "encoding": "utf8", "content": content}


REQ_HEAD = (65536 - len(TRUNCATION_MARK)) // 2  # 앞 예산(바이트)
REQ_TAIL = (65536 - len(TRUNCATION_MARK)) - REQ_HEAD
RESP_HEAD = (262144 - len(TRUNCATION_MARK)) // 2


def adversarial(rng: random.Random) -> dict[str, tuple[str, bytes]]:
    """적대 사례 — (모드, RawEnvelope 바이트). 이름 = 무엇을 겨냥하는지."""
    def T(**kw) -> dict:  # 적대 사례는 지정한 부분만 채운다(무작위 헤더·파라미터·본문 없음 — 개수 단언이 흔들리지 않게)
        kw.setdefault("headers", [])
        kw.setdefault("params", [])
        kw.setdefault("resp_headers", [])
        kw.setdefault("req_body", _utf8("", "text/plain"))
        kw.setdefault("resp_body", _utf8("", "text/plain"))
        return _tx(rng, [], **kw)

    form = "application/x-www-form-urlencoded"
    shared = "dummySharedValue42"
    c: dict[str, tuple[str, bytes]] = {}
    c["surrogate_pairs"] = ("relation_preserving", _raw(T(
        req_body=_utf8('{"password":"\\ud83d\\ude00x","n\U0001f600te":"\U0001f600","token\U0001f600":"v\U0001f600"}',
                       "application/json"),
        resp_body=_utf8("password=\U0001f600\U0001f600&user=\U0001f600", form))))
    c["control_chars"] = ("strict_redaction", _raw(T(
        req_body=_utf8('{"note":"a\\u0001b\\bc\\fd\\u001fe\\u007f\\u2028","password":"p\\tq\\nr"}', "application/json"),
        headers=[{"name": "X-Note", "value": "a\x01b\x08c\x0cd\x1fe\x7f\u2028"}])))
    c["duplicate_key_declared_json"] = ("strict_redaction", _raw(T(
        req_body=_utf8('{"password":"a","password":"b"}', "application/json"))))
    c["duplicate_key_declared_text"] = ("strict_redaction", _raw(T(
        req_body=_utf8('{"password":"a","password":"b"}', "text/plain"))))
    c["nan_declared_json"] = ("strict_redaction", _raw(T(req_body=_utf8('{"password":"a","n":NaN}', "application/json"))))
    c["mark_in_original"] = ("strict_redaction", _raw(T(req_body=_utf8(f"a=b&password=c{TRUNCATION_MARK}", form))))
    c["empty_bodies"] = ("strict_redaction", _raw(T(req_body=_utf8("", "text/plain"), resp_body=_utf8("", form))))
    c["empty_declared_json"] = ("strict_redaction", _raw(T(req_body=_utf8("", "application/json"))))
    c["nested_json_keys"] = ("relation_preserving", _raw(T(req_body=_utf8(json.dumps(
        {"a": {"password": "x1dummy", "list": [{"token": "y1dummy"}, {"Token": "x1dummy"}]}, "pwd": "z1dummy",
         "a/b": {"t~k": {"access_token": "w1dummy"}}}), "application/json"))))
    c["form_glob_case_and_percent"] = ("relation_preserving", _raw(T(req_body=_utf8(
        "PassWord=dummyA1&ACCESS_TOKEN=dummyB2&%70assword=dummyC3&pass%77ord=dummyD4&x=1&password=&password&"
        "id_token=dummy%20E5+f&q=%zz%e0%80%ff%fe", form))))
    c["form_invalid_utf8_value"] = ("relation_preserving", _raw(T(req_body=_utf8(
        "password=%ed%a0%80dummy&token=%f0%9f%98&secret=%c0%af", form))))
    c["relation_repeats"] = ("relation_preserving", _raw(T(
        headers=[{"name": "Authorization", "value": shared}, {"name": "X-Auth-Token", "value": shared},
                 {"name": "Cookie", "value": f"sid={shared}"}],
        req_body=_utf8(json.dumps({"password": shared, "token": "dummyOther9"}), "application/json"),
        params=[{"name": "password", "value": shared, "location": "form"},
                {"name": "password", "value": "dummyQueryValue1", "location": "query"}],
        resp_body=_utf8(f"token={shared}&token=dummyOther9", form))))
    c["header_name_case"] = ("strict_redaction", _raw(T(headers=[
        {"name": "AUTHORIZATION", "value": "Bearer dummyTokenAbc123"}, {"name": "cOOkie", "value": "a=dummyCookie123"},
        {"name": "HOST", "value": "juice-shop.local"}, {"name": "x-\u0130token", "value": "dummyTurkish1"},
        {"name": "X-Töken-Σ", "value": "dummySigma123"}])))
    c["unicode_space_secret_parts"] = ("strict_redaction", _raw(T(
        headers=[{"name": "Cookie", "value": "a=dummyCookieAAA1\u00a0;\u3000b=dummyCookieBBB2\u2028,c=x"},
                 {"name": "Authorization", "value": "Bearer\u00a0dummyNbspToken9"}])))
    c["leak_masked_value_in_path"] = ("strict_redaction", _raw(T(
        headers=[{"name": "X-Api-Key", "value": "dummyLeakKey77"}], path="/api/dummyLeakKey77")))
    c["leak_secret_fragment_in_body"] = ("strict_redaction", _raw(T(
        headers=[{"name": "Cookie", "value": "sid=dummyFragment88; theme=dark"}],
        resp_body=_utf8("see dummyFragment88 here", "text/plain"))))
    c["leak_encoded_form_value"] = ("strict_redaction", _raw(T(
        req_body=_utf8("password=dummy%41Enc", form), resp_body=_utf8("echo dummy%41Enc", "text/plain"))))
    c["json_escaped_key_and_value"] = ("relation_preserving", _raw(T(req_body=_utf8(
        '{"pass\\u0077ord":"a\\nb\\u00e9\\"q","to\\/ken":"x\\\\y","n":[1,2,{"pwd":"\\ud83d\\ude00"}]}',
        "application/json"))))
    c["cp_order_of_paths"] = ("strict_redaction", _raw(T(req_body=_utf8(json.dumps(
        {"token\ufffd": "dummyA1", "token\U0001f600": "dummyB2", "token\uffff": "dummyC3", "token~": "dummyD4"},
        ensure_ascii=False), "application/json"))))
    c["lone_surrogate_escape_hi"] = ("strict_redaction", _raw(T(req_body=_utf8('{"password":"\\ud800x"}', "application/json"))))
    c["lone_surrogate_escape_lo"] = ("strict_redaction", _raw(T(req_body=_utf8('{"note":"\\udc00","password":"p"}',
                                                                               "application/json"))))
    c["lone_surrogate_escape_in_key"] = ("strict_redaction", _raw(T(req_body=_utf8('{"\\ud83dpassword":"p"}', "text/plain"))))
    c["valid_pair_escape"] = ("strict_redaction", _raw(T(req_body=_utf8('{"password":"\\uD83D\\uDE00"}', "application/json"))))
    c["escaped_backslash_u"] = ("strict_redaction", _raw(T(req_body=_utf8('{"password":"\\\\ud800"}', "application/json"))))
    c["surrogate_outside_string"] = ("strict_redaction", _raw(T(req_body=_utf8("a \\ud800 b password=x", form))))
    c["depth_255"] = ("strict_redaction", _raw(T(req_body=_utf8("[" * 254 + '{"password":"dummyDeep255"}' + "]" * 254,
                                                                  "application/json"))))
    c["depth_256"] = ("strict_redaction", _raw(T(req_body=_utf8("[" * 255 + '{"password":"dummyDeep256"}' + "]" * 255,
                                                                  "application/json"))))
    c["depth_brackets_in_strings"] = ("strict_redaction", _raw(T(req_body=_utf8(
        json.dumps({"password": "[" * 300, "note": "{" * 300}), "application/json"))))
    c["depth_text_body"] = ("strict_redaction", _raw(T(req_body=_utf8("]]]" + "{" * 256, "text/plain"))))
    c["bom_declared_json"] = ("strict_redaction", _raw(T(req_body=_utf8('\ufeff{"password":"x"}', "application/json"))))
    c["bom_declared_text"] = ("strict_redaction", _raw(T(req_body=_utf8('\ufeff{"password":"x"}', "text/plain"))))
    c["utf8_content_null_and_omitted_with_content"] = ("strict_redaction", _raw(T(
        req_body={"content_type": "text/plain", "encoding": "utf8", "content": None},
        resp_body={"content_type": "text/plain", "encoding": "omitted", "content": "dummy"})))
    # 절단 — 요청 64KiB 앞 경계에 걸친 FILLER(통째로 잘린 영역으로)
    k = REQ_HEAD - 3 - 14
    c["truncate_filler_at_head"] = ("relation_preserving", _raw(T(req_body=_utf8(
        "pad=" + "x" * k + "&password=dummyHeadSecret1&tail=" + "y" * 40000, form))))
    # 뒤 경계에 걸친 FILLER
    q = REQ_TAIL - 7
    c["truncate_filler_at_tail"] = ("relation_preserving", _raw(T(req_body=_utf8(
        "a=" + "x" * 40000 + "&password=dummyTailSecret2&b=" + "y" * q, form))))
    # 가운데에서 버려지는 span 여러 개 + 양끝에 남는 span(영수증 집계)
    mid = "&".join(f"password=dummyMid{i:03d}" for i in range(50))
    c["truncate_drops_middle_spans"] = ("strict_redaction", _raw(T(req_body=_utf8(
        "token=dummyFirst1&pad=" + "x" * 40000 + "&" + mid + "&pad2=" + "y" * 40000 + "&token=dummyLast2", form))))
    # 응답 256KiB 앞 경계에 걸친 json span(json → text span 변환)
    kj = RESP_HEAD - 3 - 22
    c["truncate_json_span_at_head"] = ("strict_redaction", _raw(T(resp_body=_utf8(
        '{"pad":"' + "x" * kj + '","password":"dummyJsonSecret3","more":"' + "z" * 140000 + '","token":"dummyEnd4"}',
        "application/json"))))
    # 비ASCII 경계(3·4바이트 문자가 경계에 걸림)
    c["truncate_non_ascii_3byte"] = ("strict_redaction", _raw(T(req_body=_utf8("가" * 30000, "text/plain"))))
    c["truncate_non_ascii_4byte"] = ("strict_redaction", _raw(T(req_body=_utf8("a" + "\U0001f600" * 20000, "text/plain"))))
    c["truncate_non_ascii_2byte_response"] = ("strict_redaction", _raw(T(resp_body=_utf8("é" * 140000 + "b",
                                                                                          "text/plain"))))
    c["exactly_at_limit"] = ("strict_redaction", _raw(T(req_body=_utf8("x" * 65536, "text/plain"))))
    c["one_over_limit"] = ("strict_redaction", _raw(T(req_body=_utf8("x" * 65537, "text/plain"))))
    c["label_space_exhausted"] = ("relation_preserving", _raw(T(resp_body=_utf8(json.dumps(
        {f"token{i}": f"dummyLabel{i}" for i in range(10000)}), "application/json"))))
    c["many_labels_strict"] = ("strict_redaction", _raw(T(resp_body=_utf8(json.dumps(
        {f"token{i}": f"dummyLabel{i}" for i in range(10000)}), "application/json"))))
    c["multi_transaction"] = ("relation_preserving", _raw(T(headers=[{"name": "Cookie", "value": f"sid={shared}"}]),
                                                           T(headers=[{"name": "Cookie", "value": f"sid={shared}"}])))
    c["unknown_mode"] = ("lenient_mode", _raw(T()))
    # 입력 단계
    c["input_not_utf8"] = ("strict_redaction", b'{"schema_version":"1.0","transactions":[\xff]}')
    c["input_not_json"] = ("strict_redaction", b"not json")
    c["input_bom"] = ("strict_redaction", b"\xef\xbb\xbf" + _raw(T()))
    c["input_dup_key"] = ("strict_redaction", b'{"schema_version":"1.0","schema_version":"1.0","transactions":[]}')
    c["schema_version_2"] = ("strict_redaction", _raw(T()).replace(b'"1.0"', b'"2.0"', 1))
    c["no_transactions"] = ("strict_redaction", b'{"schema_version":"1.0","transactions":[]}')
    tx = T()
    tx["request"]["extra"] = "x"
    c["extra_field"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["request"]["path"] = "/a?b=1"
    c["path_with_query"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["request"]["port"] = 70000
    c["port_out_of_range"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["request"]["port"] = True
    c["port_bool"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["response"]["status"] = "200"
    c["status_string"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["response"]["status"] = 200.0
    c["status_float"] = ("strict_redaction", _raw(tx))
    tx = T()
    del tx["response"]["elapsed_ms"]
    c["missing_nullable_field"] = ("strict_redaction", _raw(tx))
    tx = T()
    tx["request"]["body"]["encoding"] = "gzip"
    c["unknown_encoding"] = ("strict_redaction", _raw(tx))
    return c


BASE64_BODY = {"content_type": "application/octet-stream", "encoding": "base64",
               "content": base64.b64encode(b"dummy binary \x00\x01 password=dummyB64Secret").decode("ascii")}


def _alt_policies(work: Path) -> tuple[list[Path], list]:
    """정책 1번부터: object_id_rules 비어 있지 않음, 모르는 matcher, '?' glob·keep 규칙."""
    base = json.loads(sanitization_policy.POLICY_PATH.read_text(encoding="utf-8"))
    variants = []
    v = dict(base, object_id_rules=[{"matcher": "query:*id", "action": "pseudonymize"}])
    variants.append(v)
    v = dict(base, body_rules=[*base["body_rules"], {"matcher": "xml:password", "action": "redact"}])
    variants.append(v)
    v = dict(base, policy_version="dummy-policy-q",
             header_rules=[{"name_pattern": "x-?pi-key", "action": "redact"}, {"name_pattern": "cookie", "action": "keep"},
                           {"name_pattern": "*", "action": "keep"}],
             body_rules=[{"matcher": "json:pa?sword", "action": "redact"}, {"matcher": "form:*TOK*", "action": "pseudonymize"},
                         {"matcher": "json:token", "action": "keep"}])
    variants.append(v)
    paths, models = [], []
    for i, doc in enumerate(variants, start=1):
        p = work / f"policy-{i}.json"
        p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        paths.append(p)
        models.append(sanitization_policy.load_policy(p))
    return paths, models


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    """(사례 id, 모드, 정책 번호, 바이트) 목록 + 참조 결과 + 정책 파일. 모듈마다 한 번 만든다."""
    work = tmp_path_factory.mktemp("parity")
    rng = random.Random(SEED)
    cases = []
    for i in range(160):
        pool = [_tok(rng) for _ in range(3)]
        mode = rng.choice(masker.MODES)
        txs = [_tx(rng, pool) for _ in range(rng.randint(1, 3))]
        cases.append((f"seed{i:03d}", mode, 0, _raw(*txs)))
    for name, (mode, raw) in adversarial(random.Random(SEED + 1)).items():
        cases.append((name, mode, 0, raw))
    policy_paths, policy_models = _alt_policies(work)
    rng2 = random.Random(SEED + 2)
    for idx in (1, 2, 3):
        for j in range(4):
            pool = [_tok(rng2)]
            cases.append((f"policy{idx}_{j}", rng2.choice(masker.MODES), idx, _raw(_tx(rng2, pool))))
    policies = [masker.POLICY, *policy_models]
    ref = [_reference(raw, mode, policies[idx], work, n) for n, (_, mode, idx, raw) in enumerate(cases)]
    return {"cases": cases, "ref": ref, "policies": policy_paths, "work": work}


def _java_results(corpus, classpath=None, jvm=()) -> list[tuple]:
    lines = run_java([(m, i, r) for _, m, i, r in corpus["cases"]], corpus["policies"], classpath, jvm)
    return [_parse_java(line) for line in lines]


# ─────────────────────────────── 동등성
def test_java_core_output_equals_reference_masker_bytes(corpus):
    java = _java_results(corpus)
    diffs = compare([c[0] for c in corpus["cases"]], java, corpus["ref"])
    assert diffs == [], "Java ≠ 참조 마스커:\n" + "\n".join(diffs[:40])


def test_corpus_reaches_every_area_it_claims(corpus):
    """코퍼스가 동등성 범위의 각 영역에 실제로 닿는지 — 결과에서 센다(빈 코퍼스로 '통과'하지 않게)."""
    ref = dict(zip([c[0] for c in corpus["cases"]], corpus["ref"]))
    codes = {r[1] for r in corpus["ref"] if r[0] == "REJECT"}
    assert {"input_not_json", "unknown_schema_version", "raw_schema_invalid", "unknown_mode", "body_unparseable",
            "object_id_rules_unsupported", "policy_matcher_unknown", "label_space_exhausted",
            "masked_value_leaked"} <= codes, codes
    seed = [r for c, r in zip(corpus["cases"], corpus["ref"]) if c[0].startswith("seed")]
    assert sum(r[0] == "OK" for r in seed) >= 0.9 * len(seed), "무작위 코퍼스 대부분이 거부로 끝나면 비교가 얇다"
    oks = [json.loads(b) for r in corpus["ref"] if r[0] == "OK" for _, b in r[1]]
    bodies = [tx[side]["body"] for e in oks for tx in e["transactions"] for side in ("request", "response")]
    spans = [s for b in bodies for s in b["masked_spans"]]
    assert any(b["truncated"] for b in bodies)
    assert any(s["at"]["kind"] == "json" for s in spans) and any(s["at"]["kind"] == "text" for s in spans)
    assert any(s["ref"]["label"] for s in spans) and any(s["ref"]["label"] is None for s in spans)
    assert any(b["encoding"] == "omitted" for b in bodies)
    receipts = [tx["meta"]["sanitization"] for e in oks for tx in e["transactions"]]
    assert any(r["redacted_count"] > 0 for r in receipts)
    # 표지 든 원본·고립 서로게이트·깊이 256은 omitted, 깊이 255는 마스킹됨
    for name in ("mark_in_original", "lone_surrogate_escape_hi", "lone_surrogate_escape_lo", "depth_256",
                 "depth_text_body"):
        body = json.loads(ref[name][1][0][1])["transactions"][0]["request"]["body"]
        assert body["encoding"] == "omitted", name
    body = json.loads(ref["depth_255"][1][0][1])["transactions"][0]["request"]["body"]
    assert body["encoding"] == "utf8" and body["masked_spans"], "depth_255"
    # 절단으로 버린 span도 영수증에 센다
    e = json.loads(ref["truncate_drops_middle_spans"][1][0][1])["transactions"][0]
    kept = len(e["request"]["body"]["masked_spans"])
    assert e["meta"]["sanitization"]["redacted_count"] == 52 and kept < 52
    assert e["meta"]["sanitization"]["redacted_kinds"]["token"] == 52


def test_java_always_omits_base64_bodies(corpus):
    """base64는 동등성 범위 밖 — Java는 디코드하지 않고 항상 omitted로 보낸다((A) §2.9)."""
    rng = random.Random(SEED + 3)
    raws = [_raw(_tx(rng, [], req_body=dict(BASE64_BODY), resp_body=dict(BASE64_BODY, content="!!not-base64!!"))),
            _raw(_tx(rng, [], req_body=dict(BASE64_BODY, content=None)))]
    for line in run_java([("strict_redaction", 0, r) for r in raws]):
        res = _parse_java(line)
        assert res[0] == "OK"
        for _, data in res[1]:
            for tx in json.loads(data)["transactions"]:
                for side in ("request", "response"):
                    body = tx[side]["body"]
                    if body["content_type"] == "application/octet-stream":
                        assert body == {"content_type": "application/octet-stream", "size_bytes": 0, "truncated": False,
                                        "encoding": "omitted", "content": None, "masked_spans": []}


def test_harness_classpath_has_gson_only_and_no_error_prone():
    cp = [*_build_classpath(), _gson_jar()]
    assert not any("error_prone" in str(p) for p in cp)
    assert [p.name for p in cp if p.suffix == ".jar"] == ["gson-2.15.0.jar"]


def test_policy_resource_is_the_canonical_file():
    res = BUILD / "resources" / "main" / CORE_PKG / "sanitization_policy.json"
    assert res.read_bytes() == sanitization_policy.POLICY_PATH.read_bytes()
    assert not list(PROJECT.glob("src/**/sanitization_policy.json")), "burp-extension에 정책 사본을 커밋하지 않는다"


def test_java_reason_codes_equal_reference():
    text = (PROJECT / "src/main/java" / CORE_PKG / "MaskerRejected.java").read_text(encoding="utf-8")
    block = text[text.index("REASON_CODES = List.of("):text.index(");", text.index("REASON_CODES = List.of("))]
    assert tuple(re.findall(r'"([a-z_]+)"', block)) == masker.REASON_CODES


def test_java_constants_equal_reference():
    text = (PROJECT / "src/main/java" / CORE_PKG / "Masker.java").read_text(encoding="utf-8")
    assert f'FILLER = "{FILLER}"' in text and f'TRUNCATION_MARK = "{TRUNCATION_MARK}"' in text
    assert "REQUEST_LIMIT = 64 * 1024" in text and "RESPONSE_LIMIT = 256 * 1024" in text
    assert masker.TRUNCATE_LIMIT == {"request": 64 * 1024, "response": 256 * 1024}
    amb = (PROJECT / "src/main/java" / CORE_PKG / "AmbiguousJson.java").read_text(encoding="utf-8")
    assert f"NESTING_LIMIT = {masker.NESTING_LIMIT};" in amb


def test_mismatch_report_carries_no_values():
    a = [("OK", [("x.json", json.dumps({"k": "dummySecretValue"}).encode())])]
    b = [("OK", [("x.json", json.dumps({"k": "dummyOtherValue"}).encode())])]
    report = compare(["case1"], a, b)
    assert report == ["case1#0: /k value"]
    assert "dummy" not in "".join(report)


# ─────────────────────────────── 변이 확인(변이본 로드 표지 확인 후 결과 해석)
JAVA_MUTATIONS = {
    # 직렬화기 이스케이프 하나(\b) → 동등성 실패
    "canonical_escape_b": ("Canonical.java", 'out.append("\\\\b");', 'out.append("\\\\u0008");'),
    # 경계 FILLER 통째 버림 생략 → 동등성 실패
    "truncate_head_filler_kept_half": ("Masker.java", "                head = f.start();\n", ""),
    # 영수증에서 절단으로 버린 span 미집계 → 동등성 실패
    "receipt_skips_dropped_spans": ("Masker.java", "        b.droppedKinds.addAll(cut.droppedKinds());\n", ""),
    # 고립 서로게이트 사전 검사 제거 → 동등성 실패
    "lone_surrogate_precheck_removed": ("AmbiguousJson.java", "if (loneSurrogateAt(content, i, unit)) {",
                                        "if (false) {"),
}


def _compile_mutant(tmp: Path, file: str, old: str, new: str) -> tuple[Path, Path]:
    rel = f"src/main/java/{CORE_PKG}/{file}"
    mutant = copy_with_mutation(PROJECT, ["src"], tmp / "mut", rel, old, new)
    out = tmp / "classes"
    # Montoya를 쓰지 않는 소스 전체(main·test) — 하네스가 다른 Montoya 0 패키지(capture.core 등)를 참조해도 컴파일된다
    sources = [str(p) for p in (tmp / "mut" / "src").rglob("*.java") if "burp.api" not in p.read_text(encoding="utf-8")]
    r = subprocess.run([str(_java("javac")), "--release", "17", "-encoding", "UTF-8", "-nowarn", "-cp", str(_gson_jar()),
                        "-d", str(out), *sources], capture_output=True, timeout=600)
    assert r.returncode == 0, "변이본 컴파일 실패"
    (out / CORE_PKG).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sanitization_policy.POLICY_PATH, out / CORE_PKG / "sanitization_policy.json")
    return out, mutant


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _assert_loaded_from(log: Path, class_dir: Path) -> None:
    """-Xlog:class+load 기록에서 Masker 클래스의 출처가 변이본 컴파일 폴더인지 확인한다."""
    text = log.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"sentinel\.burp\.transport\.masker\.Masker source: file:/?(\S+)", text)
    if not m:
        raise MutationNotApplied("Masker 클래스 로드 기록 없음")
    if _norm(m.group(1)) != _norm(str(class_dir)):
        raise MutationNotApplied("실행이 변이본 클래스를 쓰지 않음")


def _xlog(log: Path) -> str:
    return f'-Xlog:class+load=info:file="{log}"'


@pytest.mark.parametrize("name", sorted(JAVA_MUTATIONS))
def test_parity_is_load_bearing_under_verified_java_mutation(tmp_path, corpus, name):
    file, old, new = JAVA_MUTATIONS[name]
    classes, _ = _compile_mutant(tmp_path, file, old, new)
    log = tmp_path / "load.log"
    java = _java_results(corpus, classpath=[classes, _gson_jar()],
                         jvm=[_xlog(log)])
    _assert_loaded_from(log, classes)
    diffs = compare([c[0] for c in corpus["cases"]], java, corpus["ref"])
    assert diffs, f"변이 {name}가 동등성을 통과함(살아남음)"


def test_unmutated_copy_compiled_the_same_way_passes_as_control(tmp_path, corpus):
    """대조: 변이 없는 복사본을 같은 방법(javac)으로 컴파일하면 동등성을 통과한다 — 변이 실패가 장치 탓이 아님을 보인다."""
    classes, _ = _compile_mutant(tmp_path, "Masker.java", "public final class Masker {", "public final class Masker  {")
    log = tmp_path / "load.log"
    java = _java_results(corpus, classpath=[classes, _gson_jar()],
                         jvm=[_xlog(log)])
    _assert_loaded_from(log, classes)
    assert compare([c[0] for c in corpus["cases"]], java, corpus["ref"]) == []


# ─────────────────────────────── 산출물 신선도 표지(pytest만 따로 돌릴 때 오래된 빌드로 비교하지 않게)
def test_build_artifacts_match_current_sources():
    assert not java_build.stale_build(PROJECT)


@pytest.mark.parametrize("change", ["java_source", "policy_file", "marker_missing"])
def test_stale_build_is_detected(tmp_path, change):
    """위조: 소스(Java·정책 정본)가 빌드 뒤에 바뀌었거나 표지가 없으면 '오래됨'으로 판정한다."""
    project = tmp_path / "burp-extension"
    shutil.copytree(PROJECT / "src", project / "src")
    (project / "build").mkdir()
    (tmp_path / "src" / "sentinel").mkdir(parents=True)
    shutil.copyfile(sanitization_policy.POLICY_PATH, tmp_path / "src" / "sentinel" / "sanitization_policy.json")
    (project / "build" / "source-digest.txt").write_bytes(java_build.source_digest(project).encode("utf-8"))
    assert not java_build.stale_build(project)  # 대조: 같은 소스면 신선
    if change == "java_source":
        f = project / "src/main/java" / CORE_PKG / "Masker.java"
        f.write_text(f.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    elif change == "policy_file":
        f = tmp_path / "src" / "sentinel" / "sanitization_policy.json"
        f.write_bytes(f.read_bytes() + b"\n")
    else:
        (project / "build" / "source-digest.txt").unlink()
    assert java_build.stale_build(project)


# ─────────────────────────────── 정책 로더: glob은 ASCII, '['·']' 없음(Python·Java 같은 정의 — 기동 거부)
@pytest.mark.parametrize("pattern", ["x-[ab]pi-key", "x-api]key", "x-t\u00f6ken", "json:pass\u0077\u00f6rd"])
def test_both_policy_loaders_refuse_bracket_and_non_ascii_globs(tmp_path, pattern):
    base = json.loads(sanitization_policy.POLICY_PATH.read_text(encoding="utf-8"))
    if pattern.startswith("json:"):
        base["body_rules"] = [*base["body_rules"], {"matcher": pattern, "action": "redact"}]
    else:
        base["header_rules"] = [*base["header_rules"], {"name_pattern": pattern, "action": "redact"}]
    bad = tmp_path / "policy-bad.json"
    bad.write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError):
        sanitization_policy.load_policy(bad)
    rng = random.Random(SEED + 9)
    [line] = run_java([("strict_redaction", 1, _raw(_tx(rng, [])))], [bad])
    assert line == "POLICY_INVALID"


def test_canonical_policy_passes_both_loaders_as_control():
    assert sanitization_policy.load_policy() == sanitization_policy.DEFAULT_POLICY
    rng = random.Random(SEED + 10)
    [line] = run_java([("strict_redaction", 0, _raw(_tx(rng, [])))])
    assert line.startswith(("OK", "REJECT"))
