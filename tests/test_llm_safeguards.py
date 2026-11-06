"""어댑터 주변 안전장치 — (A) §2.8, §3.1 `llm_concurrency`, §3.3 `llm_io_audit`·`audit_write_failure`. 파이프라인 결선 없음.

감사는 합성 `LlmRun`으로, 동시성은 ASGI 호출로 증명한다. 실제 어댑터 호출은 없다.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

import pytest

from sentinel import audit
from sentinel.audit import attach_audit_store, detach_audit_store, read_audit_events, write_required
from sentinel.pipeline import entry, execution, rule_engine
from sentinel.pipeline.execution import LlmRun
from sentinel.pipeline.output_gate import LlmFailure
from sentinel.server.app import create_app
from tools.mutation_guard import copy_with_mutation
from tests.support.audit_files import audit_store_bytes
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_rule_wiring import TX, _envelope_with, _run_mutant
from tests.test_schema import _env, _raw

REPO_ROOT = Path(__file__).resolve().parents[1]
EMPTY = json.dumps({"findings": [], "advisory_signals": []})
MODEL = "m@sha256:abc"


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "audit.sqlite3"
    handler = attach_audit_store(path)
    yield path
    detach_audit_store(handler)


def _run(output, view="view", elapsed_ms=7) -> LlmRun:
    return LlmRun(MODEL, "p1", output, view, elapsed_ms)


def _respond(run: LlmRun):
    return execution.build_execution_response(_envelope_with(TX), {}, run)


def _calls(store: Path) -> list[str]:
    return [e["message"] for e in read_audit_events(store) if e["event"] == "llm_call"]


# ── 감사(지문) ─────────────────────────────────────────────────────

def test_llm_call_leaves_a_fingerprint(store):
    _respond(_run(EMPTY, view="view text"))
    [message] = _calls(store)
    assert f"view_sha256={hashlib.sha256('view text'.encode()).hexdigest()}" in message and "view_bytes=9" in message
    assert f"output_sha256={hashlib.sha256(EMPTY.encode()).hexdigest()}" in message and f"output_bytes={len(EMPTY)}" in message
    assert "elapsed_ms=7" in message and "outcome=ok" in message and "prompt_version=p1" in message and f"model_id={MODEL}" in message


@pytest.mark.parametrize("output, expected", [("not json", "rejected"), (LlmFailure("timeout"), "failed:timeout")], ids=["rejected", "failed"])
def test_fingerprint_records_the_outcome(store, output, expected):
    _respond(_run(output))
    assert f"outcome={expected}" in _calls(store)[0]


def test_fingerprint_keeps_no_content(store):
    marker = secrets.token_hex(8)
    _respond(_run(json.dumps({"findings": [], "advisory_signals": [], "x": marker}), view=f"view {marker}"))
    assert marker.encode() not in audit_store_bytes(store)


def test_rule_only_path_leaves_no_llm_fingerprint(store):
    execution.build_execution_response(_envelope_with(TX), {})
    assert _calls(store) == []


# ── 감사 기록 실패 ─────────────────────────────────────────────────

def test_write_required_says_when_nothing_is_stored():
    assert write_required("x y") is False


def test_write_required_says_when_the_store_is_broken(tmp_path):
    handler = attach_audit_store(tmp_path / "audit.sqlite3")
    handler._conn.close()
    try:
        assert write_required("x y") is False
    finally:
        audit.audit_log.removeHandler(handler)


def test_write_required_says_when_it_was_stored(store):
    assert write_required("event_name value") is True
    assert [e["event"] for e in read_audit_events(store)] == ["event_name"]


def test_llm_result_is_discarded_when_the_fingerprint_cannot_be_written(monkeypatch):
    llm_finding = {"category": "access_control", "hypothesis": "h", "claim_basis": "observed", "limitations": [], "next_steps": [],
                   "evidence": [{"transaction_ref": str(TX.meta.transaction_id), "pointer": {"locus": "resp_status"}, "observation": "o"}]}
    monkeypatch.setattr(audit, "write_required", lambda message: False)
    response = _respond(_run(json.dumps({"findings": [llm_finding], "advisory_signals": []})))
    assert response.analysis_status == "completed" and response.skipped_reasons == ["llm_failed:audit_write"]
    assert response.result.analysis_meta.llm_outcome == "failed:audit_write"
    assert {f.produced_by for f in response.result.findings} == {"rule"}  # 규칙 결과는 유지


def test_audit_failure_with_no_findings_is_not_clean(monkeypatch):
    monkeypatch.setattr(audit, "write_required", lambda message: False)
    monkeypatch.setattr(rule_engine, "evaluate", lambda tx: [])
    response = _respond(_run(EMPTY))
    assert response.result.findings == () and not response.is_clean


def test_rule_only_path_does_not_need_the_audit_store():
    assert execution.build_execution_response(_envelope_with(TX), {}).analysis_status == "completed"


# ── 동시성 ─────────────────────────────────────────────────────────

async def _call(app, token: bytes) -> list[dict]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": _raw(_env()), "more_body": False}

    async def send(message):
        sent.append(message)

    await app(_scope([(HEADER, token)]), receive, send)
    return sent


def test_token_check_answers_while_an_analysis_is_running(token, monkeypatch):
    real = entry.analyze
    monkeypatch.setattr(entry, "analyze", lambda raw, snapshot: time.sleep(1.0) or real(raw, snapshot))
    app = create_app(token)

    async def scenario() -> tuple[int, float, bool]:
        running = asyncio.create_task(_call(app, token))
        await asyncio.sleep(0.2)
        started = time.monotonic()
        sent = await _call(app, b"wrong-token-value")
        answered = time.monotonic() - started
        done = running.done()
        await running
        return _status(sent), answered, done

    status, answered, done = asyncio.run(scenario())
    assert status == 401 and answered < 0.5 and not done


def test_only_one_analysis_runs_at_a_time(token, monkeypatch):
    real = entry.analyze
    lock = threading.Lock()
    active = [0, 0]

    def analyze(raw, snapshot):
        with lock:
            active[0] += 1
            active[1] = max(active)
        time.sleep(0.1)
        with lock:
            active[0] -= 1
        return real(raw, snapshot)

    monkeypatch.setattr(entry, "analyze", analyze)
    app = create_app(token)

    async def scenario() -> list:
        return await asyncio.gather(*(_call(app, token) for _ in range(3)))

    results = asyncio.run(scenario())
    assert [_status(sent) for sent in results] == [200, 200, 200] and active[1] == 1


def test_input_rejection_still_maps_to_http_through_the_worker_thread(token):
    sent, _ = _drive(create_app(token), _scope([(HEADER, token)]), b"{}")
    assert _status(sent) == 422


# ── 변이 확인 ──────────────────────────────────────────────────────

_S = "tests/test_llm_safeguards.py::"
EXEC = ("sentinel/pipeline/execution.py", "sentinel.pipeline.execution")
APP = ("sentinel/server/app.py", "sentinel.server.app")
AUD = ("sentinel/audit.py", "sentinel.audit")
LOG = ("sentinel/pipeline/llm_audit.py", "sentinel.pipeline.llm_audit")
MUTATIONS = {
    "audit_failure_ignored": (*EXEC, "    if llm_run is not None and not _audited(llm_run, outcome):", "    if llm_run is not None and _audited(llm_run, outcome) and False:",
                              [_S + "test_llm_result_is_discarded_when_the_fingerprint_cannot_be_written"]),
    "audit_skipped": (*EXEC, "    if llm_run is not None and not _audited(llm_run, outcome):", "    if False:", [_S + "test_llm_call_leaves_a_fingerprint"]),
    "no_store_counts_as_written": (*AUD, "    if not stores:\n        return False\n", "    if not stores:\n        return True\n",
                                   [_S + "test_write_required_says_when_nothing_is_stored"]),
    "write_error_swallowed": (*AUD, "    except sqlite3.Error:\n        return False\n    return True\n", "    except sqlite3.Error:\n        return True\n    return True\n",
                              [_S + "test_write_required_says_when_the_store_is_broken"]),
    "content_in_the_fingerprint": (*LOG, '    return audit.write_required(f"llm_call view_sha256={view_hash} ', '    return audit.write_required(f"llm_call view={view} view_sha256={view_hash} ',
                                   [_S + "test_fingerprint_keeps_no_content"]),
    "analysis_on_the_event_loop": (*APP, "result = await run_in_threadpool(lambda: entry.analyze(raw, manifest_snapshot))", "result = entry.analyze(raw, manifest_snapshot)",
                                   [_S + "test_token_check_answers_while_an_analysis_is_running"]),
    "two_at_a_time": (*APP, "ANALYSIS_CONCURRENCY: Final = 1\n", "ANALYSIS_CONCURRENCY: Final = 2\n", [_S + "test_only_one_analysis_runs_at_a_time"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_safeguard_is_load_bearing_under_verified_mutation(tmp_path, name):
    rel, module, old, new, nodes = MUTATIONS[name]
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, rel, old, new)
    _run_mutant([root, REPO_ROOT], module, nodes, mutant)
