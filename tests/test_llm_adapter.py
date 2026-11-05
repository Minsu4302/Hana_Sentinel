"""LLM 어댑터 — (A) §3.1 `llm_adapter_loopback_only`·`llm_adapter_no_target_resend`·`llm_input_from_sanitized`·`llm_adapter_bounds`,
`no_autonomous_send`의 파일 예외. 루프백 스텁으로 증명한다. 추론 서버는 돌리지 않고 파이프라인에도 연결하지 않는다."""
from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import secrets
import shutil
import sys
import time
from pathlib import Path

import pytest

import sentinel
from sentinel.pipeline import llm_adapter, sanitization_check, schema_gate
from sentinel.pipeline.llm_adapter import AdapterFailure, Limits, LlmInput, complete, llm_input
from sentinel.pipeline.sanitization_check import SanitizedEnvelope, verify_sanitization
from sentinel.schema import Header
from tools.arch_boundary import ALLOWED_SEND, SEND, engine_send_violations, scan_source
from tools.completed_path import construction_violations
from tools.llm_adapter_check import adapter_call_sites, loopback_violations
from tools.mutation_guard import copy_with_mutation
from tests.support import llm_stub
from tests.support.llm_stub import LlmStub
from tests.test_rule_wiring import _run_mutant
from tests.test_schema import _env, _raw

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(sentinel.__file__).parent
ADAPTER = Path(llm_adapter.__file__)
SOURCE = ADAPTER.read_text(encoding="utf-8")
CONNECTS: list[tuple[str, int]] = []
QUICK = Limits(max_response_bytes=1024, io_timeout_seconds=0.3, deadline_seconds=0.6)
MARGIN = 2.0


def _audit(event: str, args: tuple) -> None:
    if event == "http.client.connect":
        CONNECTS.append((args[1], args[2]))


sys.addaudithook(_audit)


def _sanitized() -> SanitizedEnvelope:
    return verify_sanitization(schema_gate.parse_envelope(_raw(_env())))


def _payload() -> LlmInput:
    return llm_input(_sanitized())


# ── 정상 ───────────────────────────────────────────────────────────

def test_reply_body_comes_back_as_it_was_sent():
    with LlmStub(llm_stub.ok(b'{"choices": []}')) as stub:
        assert complete(_payload(), stub.port) == b'{"choices": []}'


def test_request_is_a_post_to_the_constant_path_with_string_content():
    payload = _payload()
    with LlmStub(llm_stub.ok(b"{}")) as stub:
        complete(payload, stub.port)
    head, _, body = stub.requests[0].partition(b"\r\n\r\n")
    assert head.startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
    assert json.loads(body) == {"messages": [{"role": "user", "content": payload.content}]}


def test_connect_goes_only_to_the_loopback_address():
    CONNECTS.clear()
    with LlmStub(llm_stub.ok(b"{}")) as stub:
        complete(_payload(), stub.port)
    assert CONNECTS == [("127.0.0.1", stub.port)]


@pytest.mark.parametrize("port", [0, 65536, -1, True, "18765", 80.0, None])
def test_port_must_be_an_integer_in_range(port):
    with pytest.raises(ValueError):
        complete(_payload(), port)


# ── 구조: 대상 재구성 불가 ─────────────────────────────────────────

def test_input_type_has_only_the_content_field():
    assert [f.name for f in dataclasses.fields(LlmInput)] == ["content"]


def test_adapter_api_takes_no_host_or_target():
    assert list(inspect.signature(complete).parameters) == ["payload", "port", "limits"]
    assert list(inspect.signature(llm_input).parameters) == ["sanitized"]


def test_method_and_path_are_the_inference_api_constants():
    assert (llm_adapter.COMPLETIONS_METHOD, llm_adapter.COMPLETIONS_PATH) == ("POST", "/v1/chat/completions")


def test_nothing_calls_the_adapter_yet():
    assert adapter_call_sites(PACKAGE) == []


def test_planted_call_site_is_found(tmp_path):
    root = tmp_path / "sentinel"
    shutil.copytree(PACKAGE, root, ignore=shutil.ignore_patterns("__pycache__"))
    (root / "pipeline" / "planted.py").write_text("from sentinel.pipeline import llm_adapter\n", encoding="utf-8")
    assert adapter_call_sites(root) == ["pipeline/planted.py:1"]


# ── 정적: 루프백 ───────────────────────────────────────────────────

def test_adapter_source_has_no_loopback_violation():
    assert loopback_violations(SOURCE) == []


CTOR = 'conn = http.client.HTTPConnection("127.0.0.1", _checked_port(port), timeout=limits.io_timeout_seconds)'
EDITS = {
    "second_constructor": (CTOR, CTOR + '\n    other = http.client.HTTPConnection("127.0.0.1", 1)', "constructor_count=2"),
    "other_address": ('"127.0.0.1", _checked_port', '"10.0.0.1", _checked_port', "constructor_arguments"),
    "localhost": ('"127.0.0.1", _checked_port', '"localhost", _checked_port', "constructor_arguments"),
    "host_keyword": ('HTTPConnection("127.0.0.1", _checked_port(port), timeout', 'HTTPConnection(host="127.0.0.1", port=port, timeout',
                     "forbidden_keyword:host"),
    "source_address": ("timeout=limits.io_timeout_seconds)", "timeout=limits.io_timeout_seconds, source_address=None)",
                       "forbidden_keyword:source_address"),
    "https": ("http.client.HTTPConnection(", "http.client.HTTPSConnection(", "forbidden:HTTPSConnection"),
    "non_string_content": ('"content": payload.content', '"content": [{"type": "image_url"}]', "content_not_the_input_string"),
    "other_path": ("conn.request(COMPLETIONS_METHOD, COMPLETIONS_PATH,", 'conn.request(COMPLETIONS_METHOD, "/x",', "request_not_constant"),
    "other_method": ("conn.request(COMPLETIONS_METHOD, COMPLETIONS_PATH,", 'conn.request("GET", COMPLETIONS_PATH,', "request_not_constant"),
    "host_parameter": ("def complete(payload: LlmInput, port: int,", "def complete(payload: LlmInput, port: int, host: str,", "forbidden_param:host"),
    "url_parameter": ("def llm_input(sanitized: SanitizedEnvelope)", "def llm_input(sanitized: SanitizedEnvelope, url: str)", "forbidden_param:url"),
    "alias_import": ("import http.client\n", "import http.client as h\nimport http.client\n", "aliased_import:http.client"),
    "from_import": ("import http.client\n", "from http.client import HTTPConnection\nimport http.client\n", "from_http_import"),
}
APPENDS = {
    "host_assignment": ("def f(conn):\n    conn.host = 'x'\n", "forbidden_store:host"),
    "port_assignment": ("def f(conn):\n    conn.port = 1\n", "forbidden_store:port"),
    "subclass": ("class C(http.client.HTTPConnection):\n    pass\n", "subclass_of_http_client"),
    "getattr": ("def f(conn):\n    return getattr(conn, 'host')\n", "forbidden_call:getattr"),
    "tunnel": ("def f(conn):\n    conn.set_tunnel('x')\n", "forbidden:set_tunnel"),
    "tunnel_by_name": ("NAME = 'set_tunnel'\n", "forbidden:set_tunnel"),
    "connection_alias": ("C = http.client.HTTPConnection\n", "connection_reference"),
}


@pytest.mark.parametrize("name", sorted(EDITS))
def test_planted_edit_is_found(name):
    old, new, code = EDITS[name]
    assert SOURCE.count(old) >= 1
    assert code in loopback_violations(SOURCE.replace(old, new))


@pytest.mark.parametrize("name", sorted(APPENDS))
def test_planted_code_is_found(name):
    code, expected = APPENDS[name]
    assert expected in loopback_violations(SOURCE + "\n\n" + code)


# ── no_autonomous_send 파일 예외 ───────────────────────────────────

def test_engine_send_exception_is_exactly_one_file_and_one_module():
    assert ALLOWED_SEND == {"pipeline/llm_adapter.py": {"http.client"}}


def test_engine_has_no_send_outside_the_exception():
    assert engine_send_violations(PACKAGE) == []


def _tree(tmp_path) -> Path:
    root = tmp_path / "sentinel"
    shutil.copytree(PACKAGE, root, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def test_http_client_in_another_file_is_a_violation(tmp_path):
    root = _tree(tmp_path)
    (root / "pipeline" / "other.py").write_text("import http.client\n", encoding="utf-8")
    assert [v.target for v in engine_send_violations(root)] == ["http.client"]


@pytest.mark.parametrize("line", ["import socket", "import urllib.request", "import ssl", "from http import server"])
def test_other_send_module_in_the_adapter_is_a_violation(tmp_path, line):
    root = _tree(tmp_path)
    path = root / "pipeline" / "llm_adapter.py"
    path.write_text(line + "\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    assert engine_send_violations(root)


def test_scan_still_sees_http_client_as_a_send_import():
    assert {v.kind for v in scan_source("x.py", "import http.client\n")} == {SEND}


# ── 입력은 ③을 통과한 값에서만 ─────────────────────────────────────

def test_input_comes_from_the_sanitized_snapshot():
    env = schema_gate.parse_envelope(_raw(_env()))
    payload = llm_input(verify_sanitization(env))
    assert json.loads(payload.content)["transactions"][0]["meta"]["transaction_id"] == str(env.transactions[0].meta.transaction_id)


@pytest.mark.parametrize("value", ["raw string", {"transactions": []}, None], ids=["string", "dict", "none"])
def test_value_that_did_not_pass_stage_three_is_refused(value):
    with pytest.raises(TypeError):
        llm_input(value)


def test_envelope_itself_is_refused():
    with pytest.raises(TypeError):
        llm_input(schema_gate.parse_envelope(_raw(_env())))


def test_rejected_envelope_gives_no_sanitized_value():
    env = _env()
    env["transactions"][0]["response"]["body"].update(content="AKIA" + "Z" * 16, size_bytes=20)
    with pytest.raises(sanitization_check.SanitizationRejected):
        verify_sanitization(schema_gate.parse_envelope(_raw(env)))


def test_change_to_the_envelope_after_stage_three_does_not_reach_the_input():
    """Envelope은 frozen이지만 목록은 가변이다 — 스냅샷이 없으면 ③ 뒤에 넣은 평문이 어댑터까지 간다."""
    secret = "AKIA" + secrets.token_hex(8).upper()
    env = schema_gate.parse_envelope(_raw(_env()))
    sanitized = verify_sanitization(env)
    env.transactions[0].request.headers.append(Header(name="X-Late", value=secret))
    assert secret not in llm_input(sanitized).content


def test_sanitized_value_and_input_cannot_be_changed():
    sanitized = _sanitized()
    with pytest.raises(dataclasses.FrozenInstanceError):
        sanitized.transactions_json = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        llm_input(sanitized).content = "x"


def test_sanitized_and_input_are_built_at_one_place_each():
    assert construction_violations(PACKAGE) == []


PLANTS = {
    "sanitized_ctor": "from sentinel.pipeline.sanitization_check import SanitizedEnvelope\nr = SanitizedEnvelope('x')\n",
    "input_ctor": "from sentinel.pipeline.llm_adapter import LlmInput\nr = LlmInput('x')\n",
    "sanitized_isinstance_elsewhere": "from sentinel.pipeline.sanitization_check import SanitizedEnvelope\n"
                                      "def f(x):\n    return isinstance(x, SanitizedEnvelope)\n",
    "dataclass_replace": "import dataclasses\ndef f(x):\n    return dataclasses.replace(x, content='y')\n",
    "dataclass_replace_import": "from dataclasses import replace\n",
}


@pytest.mark.parametrize("name", sorted(PLANTS))
def test_planted_construction_is_found(tmp_path, name):
    root = _tree(tmp_path)
    (root / "pipeline" / "planted.py").write_text(PLANTS[name], encoding="utf-8")
    assert [v for v in construction_violations(root) if "planted.py" in v]


# ── 상한 ───────────────────────────────────────────────────────────

def _timed(stub: LlmStub) -> tuple[object, float]:
    started = time.monotonic()
    result = complete(_payload(), stub.port, QUICK)
    return result, time.monotonic() - started


def test_oversized_response_stops_with_a_reason_code():
    with LlmStub(llm_stub.endless()) as stub:
        result, _seconds = _timed(stub)
    assert result == AdapterFailure("response_too_large")


def test_response_of_exactly_the_limit_is_accepted():
    with LlmStub(llm_stub.ok(b"x" * QUICK.max_response_bytes)) as stub:
        assert complete(_payload(), stub.port, QUICK) == b"x" * QUICK.max_response_bytes


def test_silent_server_ends_with_io_timeout_within_the_deadline():
    with LlmStub(llm_stub.silent(3)) as stub:
        result, seconds = _timed(stub)
    assert result == AdapterFailure("io_timeout") and seconds < QUICK.deadline_seconds + MARGIN


def test_server_dripping_the_body_ends_at_the_deadline():
    """바이트마다 타임아웃 안에 오므로 소켓 타임아웃으로는 끝나지 않는다."""
    with LlmStub(llm_stub.drip_body(0.1, 60)) as stub:
        result, seconds = _timed(stub)
    assert result == AdapterFailure("deadline_exceeded") and seconds < QUICK.deadline_seconds + MARGIN


def test_server_dripping_the_headers_ends_at_the_deadline():
    with LlmStub(llm_stub.drip_head(0.1, 60)) as stub:
        result, seconds = _timed(stub)
    assert result == AdapterFailure("deadline_exceeded") and seconds < QUICK.deadline_seconds + MARGIN


def test_redirect_is_not_followed():
    with LlmStub(llm_stub.status(b"302 Found\r\nLocation: http://example.test/")) as stub:
        assert complete(_payload(), stub.port) == AdapterFailure("bad_status")
    assert len(stub.requests) == 1


def test_error_status_is_a_reason_code():
    with LlmStub(llm_stub.status(b"500 Internal Server Error")) as stub:
        assert complete(_payload(), stub.port) == AdapterFailure("bad_status")


def test_closed_port_is_a_reason_code():
    with LlmStub(llm_stub.ok(b"")) as stub:
        port = stub.port
    # Windows는 닫힌 포트 연결을 약 1초 재시도한다 — 그보다 긴 타임아웃으로 본다
    assert complete(_payload(), port, Limits(io_timeout_seconds=10, deadline_seconds=20)) == AdapterFailure("connect_failed")


def test_failure_carries_no_prompt_or_response_content(caplog):
    marker = secrets.token_hex(8)
    with caplog.at_level(logging.DEBUG), LlmStub(llm_stub.status(f"500 {marker}".encode())) as stub:
        result = complete(LlmInput(content=marker), stub.port)
    assert result == AdapterFailure("bad_status")
    assert marker not in repr(result) and marker not in caplog.text
    assert "reason=bad_status" in caplog.text


def test_failure_reason_is_a_closed_list():
    with pytest.raises(ValueError):
        AdapterFailure("anything")


# ── 변이 확인 ──────────────────────────────────────────────────────

_T = "tests/test_llm_adapter.py::"
ADP = ("sentinel/pipeline/llm_adapter.py", "sentinel.pipeline.llm_adapter")
SAN = ("sentinel/pipeline/sanitization_check.py", "sentinel.pipeline.sanitization_check")
SRC_MUTATIONS = {
    "snapshot_removed": (*SAN, "    return SanitizedEnvelope(transactions_json=_snapshot(envelope))\n",
                         "    class _Live(SanitizedEnvelope):\n        def __init__(self):\n            pass\n"
                         "        transactions_json = property(lambda self: _snapshot(envelope))\n    return _Live()\n",
                         [_T + "test_change_to_the_envelope_after_stage_three_does_not_reach_the_input"]),
    "input_type_not_checked": (*ADP, "    if not isinstance(sanitized, SanitizedEnvelope):\n        raise TypeError(\"어댑터 입력은 ③을 통과한 값에서만 만든다\")\n"
                               "    return LlmInput(content=sanitized.transactions_json)\n",
                               "    return LlmInput(content=getattr(sanitized, 'transactions_json', str(sanitized)))\n",
                               [_T + "test_value_that_did_not_pass_stage_three_is_refused[string]",
                                _T + "test_envelope_itself_is_refused"]),
    "size_limit_off": (*ADP, "        if size > limits.max_response_bytes:\n", "        if False:\n",
                       [_T + "test_oversized_response_stops_with_a_reason_code"]),
    "deadline_timer_off": (*ADP, "    timer.start()\n", "", [_T + "test_server_dripping_the_headers_ends_at_the_deadline"]),
    "port_not_checked": (*ADP, "    if type(port) is not int or not 1 <= port <= 65535:\n", "    if False:\n",
                         [_T + "test_port_must_be_an_integer_in_range[65536]"]),
    "loopback_replaced": (*ADP, '"127.0.0.1", _checked_port', '"localhost", _checked_port',
                          [_T + "test_adapter_source_has_no_loopback_violation",
                           _T + "test_connect_goes_only_to_the_loopback_address"]),
}
CHECK = ("tools/llm_adapter_check.py", "tools.llm_adapter_check")
ARCH = ("tools/arch_boundary.py", "tools.arch_boundary")
PATH = ("tools/completed_path.py", "tools.completed_path")
TOOL_MUTATIONS = {
    "constructor_check_off": (*CHECK, '    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n',
                              "    return _imports(tree) + _names(tree) + _request(tree) + _content(tree)\n",
                              [_T + "test_planted_edit_is_found[second_constructor]", _T + "test_planted_edit_is_found[other_address]",
                               _T + "test_planted_edit_is_found[localhost]"]),
    "names_check_off": (*CHECK, '    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n',
                        "    return _imports(tree) + _constructor(tree) + _request(tree) + _content(tree)\n",
                        [_T + "test_planted_code_is_found[host_assignment]", _T + "test_planted_code_is_found[subclass]",
                         _T + "test_planted_code_is_found[getattr]", _T + "test_planted_code_is_found[tunnel]",
                         _T + "test_planted_edit_is_found[https]", _T + "test_planted_edit_is_found[source_address]"]),
    "imports_check_off": (*CHECK, '    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n',
                          "    return _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n",
                          [_T + "test_planted_edit_is_found[alias_import]"]),
    "content_check_off": (*CHECK, '    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n',
                          "    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree)\n",
                          [_T + "test_planted_edit_is_found[non_string_content]"]),
    "request_check_off": (*CHECK, '    return _imports(tree) + _names(tree) + _constructor(tree) + _request(tree) + _content(tree)\n',
                          "    return _imports(tree) + _names(tree) + _constructor(tree) + _content(tree)\n",
                          [_T + "test_planted_edit_is_found[other_path]"]),
    "call_site_check_off": (*CHECK, '            if any("llm_adapter" in name for name in names):\n', "            if False:\n",
                            [_T + "test_planted_call_site_is_found"]),
    "exception_covers_every_file": (*ARCH, "    return [v for v in found if not _send_allowed(v, root)]\n",
                                    "    return [v for v in found if not v.target.startswith('http.client')]\n",
                                    [_T + "test_http_client_in_another_file_is_a_violation"]),
    "exception_covers_every_module": (*ARCH, 'return any(v.target == m or v.target.startswith(m + ".") for m in ALLOWED_SEND.get(rel, ()))\n',
                                      "return rel in ALLOWED_SEND\n",
                                      [_T + "test_other_send_module_in_the_adapter_is_a_violation[import socket]"]),
    "replace_check_off": (*PATH, '        if node.attr == "replace" and isinstance(node.value, ast.Name) and node.value.id == "dataclasses":\n',
                          "        if False:\n", [_T + "test_planted_construction_is_found[dataclass_replace]"]),
}


@pytest.mark.parametrize("name", sorted(SRC_MUTATIONS))
def test_adapter_guard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = SRC_MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)


@pytest.mark.parametrize("name", sorted(TOOL_MUTATIONS))
def test_adapter_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = TOOL_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], module, nodes, mutant)
