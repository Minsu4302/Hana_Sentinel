"""fixture 마스커(마스커-A) — ⓕ 경계와 격리. `engine_tools_isolation` · `engine_no_rawtransaction` · `masker_independence`
· `masker_no_send`. (A) §1.3 ⓕ, §2.7, §3.1, §3.2.

'위조 거부'로 증명한다: 레포 안 원본 경로, 모르는 버전, 원본에 섞인 마스킹 산출물, 출력에 남은 원본 값(변환 버그 모의),
변환 중 예외의 원본 조각, 엔진에 심은 tools·원본 타입 import, 마스커에 심은 엔진 파이프라인·송신 import가 모두 걸린다.
원본 픽스처는 파일로 커밋하지 않는다 — 테스트가 실행 중에 N5 더미 값(faketoken_…·*.example.test)으로 만들어 레포 밖
임시 경로에만 쓴다((A) §1.3 ⓕ 해석). 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
import sys
import traceback
import uuid
from pathlib import Path

import pytest

import tools.fixture_masker.masker as masker
from sentinel.pipeline.schema_gate import parse_envelope
from tools.arch_boundary import DYNAMIC, PIPELINE, RAW, SEND, TOOLS, scan_package, scan_source
from tools.fixture_masker.masker import MaskerRejected
from tools.fixture_masker.raw import RawEnvelope
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROOT = REPO_ROOT / "src" / "sentinel"
MASKER_ROOT = REPO_ROOT / "tools" / "fixture_masker"

# N5 더미 규칙: 토큰·쿠키 값 = faketoken_ + 16 hex, 호스트 = *.example.test. 실행마다 새로 만든다.
N5_TOKEN = re.compile(r"faketoken_[0-9a-f]{16}")
N5_HOST = re.compile(r"^[a-z0-9-]+\.example\.test$")


def _fakes() -> dict[str, str]:
    return {"host": f"api-{secrets.token_hex(4)}.example.test",
            "cookie_token": f"faketoken_{secrets.token_hex(8)}",
            "bearer_token": f"faketoken_{secrets.token_hex(8)}",
            "set_cookie_token": f"faketoken_{secrets.token_hex(8)}"}


def _raw_doc(f: dict[str, str]) -> dict:
    return {"schema_version": "1.0", "transactions": [{
        "meta": {"transaction_id": str(uuid.uuid4()), "captured_at": "2026-10-27T10:00:00+09:00", "origin_ref": "burp-1"},
        "request": {"method": "POST", "scheme": "http", "host": f["host"], "port": 3000, "path": "/rest/user/login",
                    "query_params": [{"name": "q", "value": "apple", "location": "query"}],
                    "headers": [{"name": "Host", "value": f["host"]},
                                {"name": "Cookie", "value": "sid=" + f["cookie_token"]},
                                {"name": "Authorization", "value": "Bearer " + f["bearer_token"]},
                                {"name": "Content-Type", "value": "application/json"}],
                    "body": {"content_type": "application/json", "encoding": "utf8",
                             "content": '{"email": "dummy@juice-sh.op"}'}},
        "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": "sid=" + f["set_cookie_token"]}],
                     "body": {"content_type": "text/plain", "encoding": "utf8", "content": "ok"}, "elapsed_ms": 5}}]}


def _write_raw(tmp_path: Path, doc) -> Path:
    raw = tmp_path / "raw" / "export.json"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return raw


def _markers(f: dict[str, str]) -> list[str]:
    return list(f.values())


def _cli_env() -> dict[str, str]:
    return {**os.environ, "PYTHONUTF8": "1", "PYTHONPATH": os.pathsep.join([str(REPO_ROOT / "src"), str(REPO_ROOT)])}


def _no_marker(text: str | bytes, f: dict[str, str]) -> bool:
    text = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    return not any(m in text for m in _markers(f))


@pytest.fixture
def fakes() -> dict[str, str]:
    return _fakes()


def test_test_data_follows_n5_dummy_rules(fakes, tmp_path):
    assert N5_HOST.match(fakes["host"])
    assert all(N5_TOKEN.fullmatch(v) for k, v in fakes.items() if k != "host")
    assert not masker._inside_repo(tmp_path)  # 원본은 레포 밖 임시 경로에만


def test_no_committed_file_is_a_raw_envelope():
    """원본 픽스처 파일 커밋 0: 추적되는 JSON 중 RawEnvelope로 읽히는 것이 없다."""
    tracked = subprocess.run(["git", "ls-files", "*.json"], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    for rel in tracked.stdout.split():
        try:
            RawEnvelope.model_validate_json((REPO_ROOT / rel).read_bytes())
        except Exception:
            continue
        pytest.fail(f"원본 형식 파일이 커밋됨: {rel}")


# ── 대조: 정상 변환 ────────────────────────────────────────────────

@pytest.mark.parametrize("mode,labels", [
    ("strict_redaction", [None, None, None, None]),        # (A) §2.3: strict → label=null
    ("relation_preserving", ["ref_01", "ref_02", "ref_03", "ref_04"]),
])
def test_masks_policy_headers_host_and_writes_only_masked_envelopes(fakes, tmp_path, mode, labels):
    out = tmp_path / "out"
    assert masker.run(_write_raw(tmp_path, _raw_doc(fakes)), out, mode) == 1
    [path] = list(out.iterdir())
    env = parse_envelope(path.read_bytes())  # ② 스키마로 읽힘(①②③ 교차 검증은 마스커-B2)
    tx = env.transactions[0]
    masked = {h.name: h.value for h in tx.request.headers + tx.response.headers if not isinstance(h.value, str)}
    assert {n: (v.label, v.kind) for n, v in masked.items()} == dict(zip(
        ["Host", "Cookie", "Authorization", "Set-Cookie"], zip(labels, ["host", "cookie", "token", "cookie"])))
    assert tx.request.host == "masked-host-01.invalid"
    assert [h.value for h in tx.request.headers if h.name == "Content-Type"] == ["application/json"]
    receipt = tx.meta.sanitization
    assert receipt.applied and not receipt.failed and receipt.redacted_count == 4
    assert receipt.redacted_kinds.model_dump() == {"token": 1, "cookie": 2, "pii": 0, "host": 1}
    body = tx.request.body
    assert body.truncated is False and body.masked_spans == [] and body.size_bytes == len(body.content.encode())


def test_cli_output_streams_and_files_contain_no_raw_markers(fakes, tmp_path):
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-m", "tools.fixture_masker", str(_write_raw(tmp_path, _raw_doc(fakes))),
                        str(out)], cwd=REPO_ROOT, capture_output=True, env=_cli_env())
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode().strip() == "fixture_masker masked transactions=1"
    assert _no_marker(r.stdout, fakes) and _no_marker(r.stderr, fakes)
    files = list(out.iterdir())
    assert files and all(_no_marker(p.read_bytes(), fakes) for p in files)


def test_log_records_contain_no_raw_markers(fakes, tmp_path, caplog):
    with caplog.at_level(logging.DEBUG):
        masker.run(_write_raw(tmp_path, _raw_doc(fakes)), tmp_path / "out")
    assert caplog.records and all(_no_marker(r.getMessage() + repr(r.__dict__), fakes) for r in caplog.records)


# ── 위조 거부: 입력 경계 ─────────────────────────────────────────────

@pytest.mark.parametrize("rel", ["raw_export.json", "README.md", "tools/../raw.json", "docs"])
def test_rejects_input_path_inside_repo(rel):
    with pytest.raises(MaskerRejected) as exc:
        masker.load_raw(masker.REPO_ROOT / rel)
    assert exc.value.code == "input_inside_repo"


@pytest.mark.parametrize("version", ["2.0", "1", 1.0, None, "__missing__"])
def test_rejects_unknown_or_missing_schema_version(fakes, tmp_path, version):
    doc = _raw_doc(fakes)
    if version == "__missing__":
        del doc["schema_version"]
    else:
        doc["schema_version"] = version
    with pytest.raises(MaskerRejected) as exc:
        masker.load_raw(_write_raw(tmp_path, doc))
    assert exc.value.code == "unknown_schema_version"


def _plant(doc: dict, where: str, value) -> dict:
    tx = doc["transactions"][0]
    if where == "body_masked_spans":
        tx["request"]["body"]["masked_spans"] = []
    elif where == "body_truncated":
        tx["request"]["body"]["truncated"] = False
    elif where == "body_size_bytes":
        tx["request"]["body"]["size_bytes"] = 10
    elif where == "header_masked_ref":
        tx["request"]["headers"][1]["value"] = {"masked": True, "label": "ref_01", "kind": "cookie"}
    elif where == "meta_sanitization":
        tx["meta"]["sanitization"] = {"applied": True}
    elif where == "path_with_query":
        tx["request"]["path"] = "/rest/products/search?q=" + value
    elif where == "extra_field_with_raw_value":
        tx["request"]["raw_bytes"] = value
    return doc


ARTIFACTS = ["body_masked_spans", "body_truncated", "body_size_bytes", "header_masked_ref", "meta_sanitization",
             "path_with_query", "extra_field_with_raw_value"]


@pytest.mark.parametrize("where", ARTIFACTS)
def test_rejects_mask_artifacts_or_schema_violations_in_raw_input(fakes, tmp_path, where):
    """원본에 마스킹 산출물(masked_spans·truncated·size_bytes·MaskedRef·sanitization)이 섞이면 거부 — 오류에 값 없음."""
    with pytest.raises(MaskerRejected) as exc:
        masker.load_raw(_write_raw(tmp_path, _plant(_raw_doc(fakes), where, fakes["bearer_token"])))
    assert exc.value.code == "raw_schema_invalid"
    assert _no_marker("".join(traceback.format_exception(exc.value)), fakes)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


@pytest.mark.parametrize("text", ["not json", '{"schema_version": "1.0", "schema_version": "1.0"}', "﻿{}", "[]"])
def test_rejects_non_json_or_non_strict_json(tmp_path, text):
    with pytest.raises(MaskerRejected) as exc:
        masker.load_raw(_write_raw(tmp_path, text))
    assert exc.value.code in {"input_not_json", "unknown_schema_version"}


# ── 위조 거부: 출력 유출 ─────────────────────────────────────────────

def test_leak_guard_rejects_transform_bug_and_writes_nothing(fakes, tmp_path, monkeypatch):
    """변환 버그 모의: 헤더 마스킹이 원본 값을 그대로 둔다 → 유출 검사가 거부하고 출력 디렉터리에 아무것도 없다."""
    def buggy(h, run):
        run.masked(h.value, "token")  # 마스킹했다고 기록만 하고
        return {"name": h.name, "value": h.value}  # 원본을 그대로 내보낸다
    monkeypatch.setattr(masker, "_header", buggy)
    out = tmp_path / "out"
    with pytest.raises(MaskerRejected) as exc:
        masker.run(_write_raw(tmp_path, _raw_doc(fakes)), out)
    assert exc.value.code == "masked_value_leaked"
    assert not out.exists() or list(out.iterdir()) == []


@pytest.mark.parametrize("place", ["request_body", "query_param", "referer_header", "token_only_in_body"])
def test_masked_value_also_present_in_unmasked_place_is_rejected_fail_closed(fakes, tmp_path, place):
    """A는 본문·파라미터·기타 헤더를 마스킹하지 않는다 — 마스킹한 값이 거기 또 있으면 내보내지 않는다(B에서 다룸)."""
    doc = _raw_doc(fakes)
    req = doc["transactions"][0]["request"]
    if place == "request_body":
        req["body"]["content"] = json.dumps({"note": fakes["cookie_token"]})
    elif place == "query_param":
        req["query_params"].append({"name": "t", "value": fakes["bearer_token"], "location": "query"})
    elif place == "referer_header":
        req["headers"].append({"name": "Referer", "value": f"http://{fakes['host']}/login"})
    else:  # 헤더 값 전체('sid=<토큰>')가 아니라 토큰 조각만 다른 자리에
        doc["transactions"][0]["response"]["body"]["content"] = "your token is " + fakes["set_cookie_token"]
    with pytest.raises(MaskerRejected) as exc:
        masker.run(_write_raw(tmp_path, doc), tmp_path / "out")
    assert exc.value.code == "masked_value_leaked"


def test_transform_exception_leaves_no_raw_fragment(fakes, tmp_path, monkeypatch, caplog):
    """변환 중 예외의 메시지에 원본 조각이 있어도(모의) 밖으로 나가는 예외·트레이스백·로그에는 사유 코드뿐."""
    def explode(*_args, **_kwargs):  # 서명과 무관하게 — 인자 수가 바뀌면 TypeError로 공허하게 통과했다(B1 변이가 잡음)
        raise ValueError(f"cannot handle {fakes['bearer_token']} at {fakes['host']}")
    monkeypatch.setattr(masker, "_body", explode)
    with caplog.at_level(logging.DEBUG), pytest.raises(MaskerRejected) as exc:
        masker.run(_write_raw(tmp_path, _raw_doc(fakes)), tmp_path / "out")
    assert exc.value.code == "transform_failed"
    assert _no_marker("".join(traceback.format_exception(exc.value)), fakes)
    assert all(_no_marker(r.getMessage(), fakes) for r in caplog.records)


def test_cli_rejection_prints_reason_code_only(fakes, tmp_path):
    doc = _plant(_raw_doc(fakes), "extra_field_with_raw_value", fakes["bearer_token"])
    r = subprocess.run([sys.executable, "-m", "tools.fixture_masker", str(_write_raw(tmp_path, doc)),
                        str(tmp_path / "out")], cwd=REPO_ROOT, capture_output=True, env=_cli_env())
    assert r.returncode == 2 and r.stdout == b""
    assert r.stderr.decode().strip() == "fixture_masker rejected: raw_schema_invalid"


def test_cli_unexpected_error_prints_no_traceback(fakes, tmp_path):
    out = tmp_path / "out_is_a_file"
    out.write_text("x", encoding="utf-8")  # 디렉터리 자리에 파일 → 쓰기 단계의 예상 밖 OS 오류
    r = subprocess.run([sys.executable, "-m", "tools.fixture_masker", str(_write_raw(tmp_path, _raw_doc(fakes))),
                        str(out)], cwd=REPO_ROOT, capture_output=True, env=_cli_env())
    assert r.returncode == 3 and r.stderr.decode().strip() == "fixture_masker failed: internal_error"
    assert b"Traceback" not in r.stderr and _no_marker(r.stderr + r.stdout, fakes)


# ── 격리: engine_tools_isolation · engine_no_rawtransaction ────────────────

def _pkg(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "dummy_pkg"
    for rel, src in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(src, encoding="utf-8")
    return root


def test_engine_imports_nothing_from_tools():
    assert [v.render() for v in scan_package(ENGINE_ROOT) if v.kind == TOOLS] == []


@pytest.mark.parametrize("src", [
    "import tools", "import tools.fixture_masker.masker", "from tools import secret_scan",
    "from tools.fixture_masker.raw import RawBody", "import tools.guardrails as g",
    "import importlib\nimportlib.import_module('tools.fixture_masker')", "__import__('tools')",
    "import tools\ntools.fixture_masker.masker.run('a', 'b')",
])
def test_rejects_tools_import_planted_in_engine(tmp_path, src):
    assert TOOLS in {v.kind for v in scan_package(_pkg(tmp_path, {"__init__.py": "", "planted.py": src + "\n"}))}


def test_engine_has_no_raw_transaction_names():
    assert [v.render() for v in scan_package(ENGINE_ROOT) if v.kind == RAW] == []


@pytest.mark.parametrize("src", [
    "from tools.fixture_masker.raw import RawTransaction",
    "from sentinel.common_types import RawTransaction",
    "from shared.raw_types import RawBody",
    "from .raw import RawEnvelope",
    "import somewhere.raw as r\nx = r.RawTransaction",
    "from pydantic import BaseModel\nclass RawTransaction(BaseModel):\n    pass",
])
def test_rejects_raw_transaction_wherever_it_lives(tmp_path, src):
    assert RAW in {v.kind for v in scan_package(_pkg(tmp_path, {"__init__.py": "", "planted.py": src + "\n"}))}


def test_raw_type_moved_out_of_tools_is_caught_where_tools_isolation_is_silent(tmp_path):
    """(ㄱ)의 근거: 원본 타입이 tools/ 밖(엔진 공용 모듈)으로 옮겨지면 engine_tools_isolation은 침묵하지만 이 검사는 잡는다."""
    root = _pkg(tmp_path, {
        "__init__.py": "",
        "common_types.py": "from pydantic import BaseModel\nclass RawBody(BaseModel):\n    content: str\n",
        "pipeline/__init__.py": "",
        "pipeline/stage.py": "from sentinel.common_types import RawBody\n",
    })
    kinds = {v.kind for v in scan_package(root)}
    assert TOOLS not in kinds and RAW in kinds


def test_allowed_engine_like_imports_pass_as_control(tmp_path):
    src = "import json\nfrom sentinel.schema import Envelope\nfrom sentinel import strict_json\nfrom .x import Body\n"
    assert scan_package(_pkg(tmp_path, {"__init__.py": "", "ok.py": src})) == []


# ── 격리: masker_independence · masker_no_send ──────────────────────────

def test_masker_does_not_import_engine_pipeline_but_uses_shared_strict_json():
    assert [v.render() for v in scan_package(MASKER_ROOT) if v.kind == PIPELINE] == []
    assert "from sentinel import strict_json" in (MASKER_ROOT / "masker.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("src", [
    "from sentinel.pipeline import sanitization_check",
    "import sentinel.pipeline.sanitization_check",
    "from sentinel.pipeline.sanitization_check import scan_text",
    "import sentinel.pipeline.sanitization_check as sc",
    "import sentinel\nsentinel.pipeline.sanitization_check.scan_text('x')",
    "from sentinel import pipeline",
    "from sentinel.pipeline import masked_span_check",  # 같은 ③ 로직의 형제 모듈 — 우회로
    "import importlib\nimportlib.import_module('sentinel.pipeline.sanitization_check')",
])
def test_rejects_engine_pipeline_import_planted_in_masker(tmp_path, src):
    assert PIPELINE in {v.kind for v in scan_package(_pkg(tmp_path, {"__init__.py": "", "planted.py": src + "\n"}))}


def test_shared_definitions_outside_pipeline_are_allowed_for_masker_as_control():
    src = ("from sentinel import strict_json\nfrom sentinel.schema import Envelope\n"
           "from sentinel.common_types import FILLER\nfrom sentinel.sanitization_policy import DEFAULT_POLICY\n")
    assert scan_source("ok.py", src) == []


def test_masker_has_no_send_socket_or_dynamic_import():
    assert [v.render() for v in scan_package(MASKER_ROOT) if v.kind in (SEND, DYNAMIC)] == []


@pytest.mark.parametrize("src", ["import socket", "from urllib.request import urlopen", "import requests",
                                 "from http.client import HTTPSConnection", "import asyncio\nasyncio.open_connection",
                                 "import smtplib"])
def test_rejects_send_import_planted_in_masker(tmp_path, src):
    root = _pkg(tmp_path, {"__init__.py": "", "masker.py": "from sentinel import strict_json\n", "planted.py": src + "\n"})
    assert SEND in {v.kind for v in scan_package(root)}


# ── 변이 확인: 각 검사가 하중을 지지한다(변이본 로드 먼저 증명) ───────────────────

STAMP = "fixture_masker_probe"
_DRIVER = """
import os, sys, importlib
# -c 실행은 현재 디렉터리(레포 루트)를 sys.path 맨 앞에 넣어 원본 tools/가 변이본을 가린다(표지 검사가 실제로 잡음) — 뺀다
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]
importlib.import_module(sys.argv[1])  # pytest의 pythonpath 삽입 전에 변이본을 먼저 적재
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_fixture_masker.py::"
_M = ("tools/fixture_masker/masker.py", "tools.fixture_masker.masker")
_A = ("tools/arch_boundary.py", "tools.arch_boundary")
MUTATIONS = {
    "leak_guard_off": (*_M, "    if _leaked(serialized, run.originals):\n", "    if False:\n",
                       [_T + "test_leak_guard_rejects_transform_bug_and_writes_nothing",
                        _T + "test_masked_value_also_present_in_unmasked_place_is_rejected_fail_closed"]),
    "exception_chain_kept": (*_M, '        except Exception:\n            raise MaskerRejected("transform_failed") from None',
                             '        except Exception as exc:\n            raise MaskerRejected("transform_failed") from exc',
                             [_T + "test_transform_exception_leaves_no_raw_fragment"]),
    "schema_error_chain_kept": (*_M, '    except ValidationError:\n        raise MaskerRejected("raw_schema_invalid") from None',
                                '    except ValidationError as exc:\n        raise MaskerRejected("raw_schema_invalid") from exc',
                                [_T + "test_rejects_mask_artifacts_or_schema_violations_in_raw_input"]),
    "repo_path_check_off": (*_M, "    if _inside_repo(path):\n", "    if False:\n",
                            [_T + "test_rejects_input_path_inside_repo"]),
    "version_check_off": (*_M, '    if not isinstance(doc, dict) or doc.get("schema_version") != RAW_SCHEMA_VERSION:\n',
                          "    if False:\n", [_T + "test_rejects_unknown_or_missing_schema_version"]),
    "tools_isolation_off": (*_A, "    if _under(module, TOOLS_PACKAGE):\n        return TOOLS\n", "",
                            [_T + "test_rejects_tools_import_planted_in_engine"]),
    "raw_names_off": (*_A, 'RAW_NAMES = {"RawEnvelope"', 'RAW_NAMES: set = set()\n_DISABLED = {"RawEnvelope"',
                      [_T + "test_rejects_raw_transaction_wherever_it_lives",
                       _T + "test_raw_type_moved_out_of_tools_is_caught_where_tools_isolation_is_silent"]),
    "pipeline_isolation_off": (*_A, "    if _under(module, PIPELINE_PACKAGE):\n        return PIPELINE\n", "",
                               [_T + "test_rejects_engine_pipeline_import_planted_in_masker"]),
    "send_check_off": (*_A, "    if any(_under(module, m) for m in SEND_MODULES):\n        return SEND\n", "",
                       [_T + "test_rejects_send_import_planted_in_masker"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_masker_check_is_load_bearing_under_verified_mutation(tmp_path, name):
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
