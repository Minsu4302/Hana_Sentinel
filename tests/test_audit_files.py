"""값 미기록 검사가 읽는 범위 — `tests.support.audit_files`. 곁 파일 경합은 견디되 검사 범위는 줄지 않음을 증명한다."""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from sentinel.audit import attach_audit_store, audit_log, detach_audit_store
from tests.support import audit_files
from tests.support.audit_files import audit_store_bytes
from tests.test_rule_wiring import _run_mutant
from tools.mutation_guard import copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
_A = "tests/test_audit_files.py::"
_GATE_NODE = "tests/test_output_gate.py::test_unresolvable_pointer_audit_has_no_header_name_path_or_range_values"


@pytest.fixture
def store(tmp_path) -> Path:
    path = tmp_path / "audit.sqlite3"
    path.write_bytes(b"main")
    return path


def _failing_read(monkeypatch, name: str, error: Exception, times: int | None = None) -> list[int]:
    """그 이름의 파일을 읽을 때 error를 낸다. times면 그 횟수만, 없으면 계속."""
    real, calls = Path.read_bytes, [0]

    def read_bytes(self):
        if self.name == name and (times is None or calls[0] < times):
            calls[0] += 1
            raise error
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(audit_files, "WAIT_SECONDS", 0)
    return calls


def test_value_written_through_the_audit_log_is_found(tmp_path):
    marker = secrets.token_hex(8)
    path = tmp_path / "audit.sqlite3"
    handler = attach_audit_store(path)
    audit_log.warning("output_rejected value=%s", marker)
    assert marker.encode() in audit_store_bytes(path)
    detach_audit_store(handler)


@pytest.mark.parametrize("suffix", audit_files.SIDECAR_SUFFIXES)
def test_value_in_a_readable_sidecar_is_found(store, suffix):
    (store.parent / (store.name + suffix)).write_bytes(b"leaked")
    assert b"leaked" in audit_store_bytes(store)


def test_value_in_another_file_with_the_store_prefix_is_found(store):
    (store.parent / (store.name + ".bak")).write_bytes(b"leaked")
    assert b"leaked" in audit_store_bytes(store)


def test_other_files_in_the_directory_are_not_read(store):
    (store.parent / "other.txt").write_bytes(b"unrelated")
    assert b"unrelated" not in audit_store_bytes(store)


def test_missing_main_file_fails(store):
    store.unlink()
    with pytest.raises(FileNotFoundError):
        audit_store_bytes(store)


def test_unreadable_main_file_fails(store, monkeypatch):
    _failing_read(monkeypatch, store.name, PermissionError("locked"))
    with pytest.raises(PermissionError):
        audit_store_bytes(store)


def test_vanished_sidecar_is_tolerated_and_the_main_file_is_still_read(store, monkeypatch):
    (store.parent / (store.name + "-journal")).write_bytes(b"x")
    _failing_read(monkeypatch, store.name + "-journal", FileNotFoundError())
    assert audit_store_bytes(store) == b"main"


def test_sidecar_locked_for_a_moment_is_read_after_the_retry(store, monkeypatch):
    (store.parent / (store.name + "-journal")).write_bytes(b"leaked")
    calls = _failing_read(monkeypatch, store.name + "-journal", PermissionError("deleting"), times=3)
    assert b"leaked" in audit_store_bytes(store) and calls == [3]


def test_sidecar_that_stays_locked_fails(store, monkeypatch):
    """읽지 못한 내용을 깨끗하다고 하지 않는다."""
    (store.parent / (store.name + "-journal")).write_bytes(b"x")
    _failing_read(monkeypatch, store.name + "-journal", PermissionError("locked"))
    with pytest.raises(PermissionError):
        audit_store_bytes(store)


def test_vanished_file_that_is_not_a_sidecar_fails(store, monkeypatch):
    (store.parent / (store.name + ".bak")).write_bytes(b"x")
    _failing_read(monkeypatch, store.name + ".bak", FileNotFoundError())
    with pytest.raises(FileNotFoundError):
        audit_store_bytes(store)


TEST_MUTATIONS = {
    "sidecars_skipped": ("        chunks.append(_sidecar_bytes(path) if sidecar else path.read_bytes())\n",
                         "        chunks.append(b\"\" if sidecar else path.read_bytes())\n",
                         [_A + "test_value_in_a_readable_sidecar_is_found[-journal]",
                          _A + "test_sidecar_locked_for_a_moment_is_read_after_the_retry"]),
    "lock_swallowed": ("            if attempt == ATTEMPTS - 1:\n                raise\n",
                       "            if attempt == ATTEMPTS - 1:\n                return b\"\"\n",
                       [_A + "test_sidecar_that_stays_locked_fails"]),
    "every_file_tolerated": ("        sidecar = path.name[len(store.name):] in SIDECAR_SUFFIXES\n", "        sidecar = True\n",
                             [_A + "test_vanished_file_that_is_not_a_sidecar_fails"]),
    "main_file_not_required": ("    chunks = [store.read_bytes()]\n", "    chunks = [_sidecar_bytes(store)]\n",
                               [_A + "test_missing_main_file_fails"]),
}


@pytest.mark.parametrize("name", sorted(TEST_MUTATIONS))
def test_scope_is_load_bearing_under_verified_mutation(tmp_path, name):
    old, new, nodes = TEST_MUTATIONS[name]
    root = tmp_path / "mut"
    mutant = copy_with_mutation(REPO_ROOT, ["tests/support"], root, "tests/support/audit_files.py", old, new)
    _run_mutant([root, REPO_ROOT / "src", REPO_ROOT], "tests.support.audit_files", nodes, mutant)


def test_value_leaking_into_the_audit_still_fails_the_original_check(tmp_path):
    """원래 적대: 게이트가 입력 값을 감사에 남기면 값 미기록 검사가 실패한다."""
    root = tmp_path / "mut" / "src"
    mutant = copy_with_mutation(REPO_ROOT / "src", ["sentinel"], root, "sentinel/pipeline/output_gate.py",
                                "    by_id = _checked_server_args(transactions, produced_by, analysis_meta)\n",
                                "    by_id = _checked_server_args(transactions, produced_by, analysis_meta)\n"
                                "    audit_log.warning(\"output_rejected draft=%s\", draft)\n")
    _run_mutant([root, REPO_ROOT], "sentinel.pipeline.output_gate", [_GATE_NODE], mutant)


