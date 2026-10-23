"""영구 제외 '부재 증명' — `no_autopatch_apply`(ⓓ) · `no_finetune_path`(ⓔ) · `no_raw_persistence`(ⓕ).

두 겹으로 증명한다.
1) 정적(아키텍처): 엔진 소스에 각 기능을 구현할 통로(모듈·호출·심볼)가 없다. 통로를 심은 더미는 잡힌다.
2) 런타임 관측(ⓕ): 실제 요청(수용 + 각 거부 경로)을 처리하는 동안 파일 쓰기 open이 없고, 모든 로그(DEBUG
   포함)·stdout/stderr·감사 SQLite 디렉터리의 바이트 어디에도 원문 표지가 없다. 감사 지점이 본문을 적거나
   임시파일·디버그 로그·print로 흘리는 변이를 심으면 관측이 잡는다.
R-10: `.gitignore`만으로 원본 미기록을 보장하지 않는다 — 여기서는 기능 부재 + 관측으로 보장하고, `.gitignore`는
감사 DB가 커밋되지 않는 보조 확인일 뿐이다.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import sentinel.pipeline.schema_gate as schema_gate
from sentinel.audit import attach_audit_store, audit_log, detach_audit_store, install_egress_audit_hook
from sentinel.server.app import create_app
from tools.absence_check import (
    ALLOWED, AUTOPATCH, FINETUNE, RAW_PERSIST, AbsenceScanError, scan_package, scan_source)
from tools.guardrails import REPO_ROOT
from tests.test_auth import HEADER, _drive, _scope, _status
from tests.test_sanitization import FAKES, _plant
from tests.test_schema import T0, _env, _raw, _set

ENGINE_ROOT = REPO_ROOT / "src" / "sentinel"


def _dummy(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "dummy_engine"
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return root


# ── 1) 정적: 실제 엔진 ────────────────────────────────────────────

def test_engine_has_no_autopatch_path():
    assert [f.render() for f in scan_package(ENGINE_ROOT) if f.key == AUTOPATCH] == []


def test_engine_has_no_finetune_path():
    assert [f.render() for f in scan_package(ENGINE_ROOT) if f.key == FINETUNE] == []


def test_engine_has_no_raw_persistence_path_except_allowlisted_audit_store():
    assert [f.render() for f in scan_package(ENGINE_ROOT) if f.key == RAW_PERSIST] == []
    assert ALLOWED == {"audit.py": {"module:sqlite3"}}  # 허용 예외가 몰래 늘지 않게 고정


# ── 1) 정적: 위조 거부(통로를 심은 더미) ─────────────────────────────────

PLANTED = {
    AUTOPATCH: [
        "import subprocess\nsubprocess.run(['git', 'apply', 'fix.diff'])",
        "import os\nos.system('git apply fix.diff')",
        "from os import system",
        "import os\nos.execvp('patch', ['patch'])",
        "import git",
        "from pygit2 import Repository",
        "from unidiff import PatchSet",
        "import multiprocessing",
        "def apply_patch(diff):\n    pass",
        "def apply_suggestion(s):\n    pass",
        "class AutoFixer:\n    pass",
        "async def auto_remediate(finding):\n    pass",
    ],
    FINETUNE: [
        "from transformers import Trainer",
        "from transformers import TrainingArguments",
        "import transformers\nt = transformers.Seq2SeqTrainer",
        "import peft",
        "from peft import LoraConfig",
        "from trl import SFTTrainer",
        "import accelerate",
        "import deepspeed",
        "def fine_tune(model):\n    pass",
        "def build_lora_adapter():\n    pass",
        "class DatasetForTraining_data:\n    pass",
        "def finetune_on_reports(reports):\n    pass",
    ],
    RAW_PERSIST: [
        "open('dump.bin', 'wb').write(b'x')",
        "f = open('raw.txt', mode='a')",
        "def save(p, m):\n    return open(p, m)",
        "from pathlib import Path\nPath('raw.json').write_text('x')",
        "from pathlib import Path\nPath('raw.bin').write_bytes(b'x')",
        "import tempfile",
        "import pickle",
        "import shelve",
        "import sqlite3",  # audit.py 밖
        "import logging.handlers",
        "import logging\nlogging.FileHandler('debug.log')",
        "from logging import FileHandler",
        "import os\nos.write(1, b'x')",
        "import json\njson.dump({}, fp)",
        "def debug(body):\n    print(body)",
        "import io\nio.open('x', 'w')",
    ],
}


@pytest.mark.parametrize("key,src", [(k, s) for k, srcs in PLANTED.items() for s in srcs])
def test_planted_forbidden_path_is_caught(tmp_path, key, src):
    root = _dummy(tmp_path, {"__init__.py": "", "planted.py": src + "\n"})
    assert key in {f.key for f in scan_package(root)}, src


ALLOWED_SNIPPETS = """\
import json
import logging
from pathlib import Path

log = logging.getLogger("sentinel.audit")


def load(p):
    with open(p) as f:
        a = f.read()
    with open(p, "r", encoding="utf-8") as f:
        b = f.read()
    return json.loads(Path(p).read_text()) or json.dumps(a + b)


def dump_model(m):
    log.warning("schema_rejected errors=%d", 1)
    return m.model_dump()


def train_station_name():  # 'train' 단독은 금지 아님
    return "x"
"""


def test_allowed_constructs_pass_as_control(tmp_path):
    root = _dummy(tmp_path, {"__init__.py": "", "ok.py": ALLOWED_SNIPPETS})
    assert scan_package(root) == []


def test_allowlist_is_file_specific(tmp_path):
    root = _dummy(tmp_path, {"__init__.py": "", "audit.py": "import sqlite3\n", "other.py": "import sqlite3\n"})
    found = scan_package(root)
    assert [(f.path, f.what) for f in found] == [("other.py", "module:sqlite3")]


def test_empty_or_unparseable_target_is_an_error_not_a_pass(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(AbsenceScanError):
        scan_package(tmp_path / "empty")
    with pytest.raises(AbsenceScanError):
        scan_source("broken.py", "def (:\n")


# ── 2) 런타임 관측(ⓕ) ─────────────────────────────────────────────

_MONITOR: dict = {"on": False, "events": []}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _monitor_hook(event: str, args: tuple) -> None:
    if not _MONITOR["on"]:
        return
    if event == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
                 (isinstance(flags, int) and flags & _WRITE_FLAGS)
        if writes:
            _MONITOR["events"].append(("open_write", str(path)))
    elif event in ("sqlite3.connect", "tempfile.mkstemp", "tempfile.mkdtemp", "shutil.copyfile", "os.rename"):
        _MONITOR["events"].append((event, str(args[0]) if args else ""))


sys.addaudithook(_monitor_hook)  # 제거 불가 — 플래그가 꺼져 있으면 아무것도 하지 않음


def find_leaks(markers: list[str], *, events: list, texts: list[str], files: list[Path]) -> list[str]:
    leaks = [f"file_write:{kind}" for kind, _ in events]
    blob = "\n".join(texts)
    for m in markers:
        if m in blob:
            leaks.append("log_or_stdio")
        for f in files:
            if m.encode() in f.read_bytes():
                leaks.append(f"file:{f.name}")
    return sorted(set(leaks))


def _exercise(token: bytes) -> list[str]:
    """수용 + 각 거부 경로를 원문 표지와 함께 실행. 원문이 어디로도 새면 안 되는 값들을 돌려준다."""
    body_marker, name_marker, query_marker = (secrets.token_hex(12) for _ in range(3))
    header_name = "X-" + name_marker
    presented = secrets.token_urlsafe(32)
    app = create_app(token)

    accepted = _env()
    accepted["transactions"][0]["request"]["body"].update(
        content=json.dumps({"note": body_marker}), size_bytes=40)
    accepted["transactions"][0]["request"]["headers"].append({"name": header_name, "value": "plain"})
    accepted["transactions"][0]["request"]["query_params"][0]["value"] = query_marker
    sent, _ = _drive(app, _scope([(HEADER, token)]), _raw(accepted))
    assert _status(sent) == 200

    _drive(app, _scope([(HEADER, presented.encode())], query=b"q=" + query_marker.encode()), _raw(accepted))
    _drive(app, _scope([(HEADER, token)]), _raw(_set(_env(), f"{T0}.request.port", body_marker)))
    leaky = _plant("request_body", FAKES["jwt"] + " " + body_marker)
    leaky["transactions"][0]["request"]["headers"].append({"name": header_name, "value": FAKES["aws_access_key_id"]})
    _drive(app, _scope([(HEADER, token)]), _raw(leaky))

    install_egress_audit_hook()
    egress_host = f"egress-{secrets.token_hex(4)}.invalid"
    sys.audit("socket.getaddrinfo", egress_host, 443, 0, 0, 0)
    return [token.decode(), presented, body_marker, name_marker, query_marker, egress_host,
            FAKES["jwt"], FAKES["aws_access_key_id"]]


@pytest.fixture
def observed(tmp_path, caplog, capsys):
    """요청 처리 구간을 관측: 파일 쓰기 open, 전 로거 DEBUG 출력, stdout/stderr, 감사 DB 디렉터리 바이트."""
    audit_dir = tmp_path / "var"
    handler = attach_audit_store(audit_dir / "audit.sqlite3")
    caplog.set_level(logging.DEBUG)

    def run(token: bytes) -> list[str]:
        _MONITOR.update(on=True, events=[])
        try:
            markers = _exercise(token)
        finally:
            _MONITOR["on"] = False
        detach_audit_store(handler)
        out = capsys.readouterr()
        return find_leaks(markers, events=list(_MONITOR["events"]), texts=[caplog.text, out.out, out.err],
                          files=[p for p in audit_dir.rglob("*") if p.is_file()])

    yield run
    if handler in audit_log.handlers:
        detach_audit_store(handler)


def test_runtime_request_processing_persists_no_raw_traffic(observed, token, caplog):
    assert observed(token) == []
    assert "sanitization_rejected" in caplog.text  # 대조: 감사는 실제로 남았다(관측이 비어서 통과한 게 아님)


@pytest.fixture
def leak_variants(monkeypatch):
    """변이 주입기 — 파이프라인 진입점(스키마 게이트)에서 원문을 흘린다."""
    real = schema_gate.parse_envelope

    def install(kind: str):
        def leaky(raw: bytes):
            text = raw.decode("utf-8", errors="replace")
            if kind == "audit_writes_body":
                audit_log.warning("schema_debug body=%s", text)
            elif kind == "debug_log":
                logging.getLogger("sentinel.debug").debug("raw=%s", text)
            elif kind == "print":
                print(text)
            elif kind == "tempfile":
                with tempfile.NamedTemporaryFile("wb", delete=False) as f:
                    f.write(raw)
                os.unlink(f.name)
            return real(raw)

        monkeypatch.setattr(schema_gate, "parse_envelope", leaky)

    return install


@pytest.mark.parametrize("kind,expected", [
    ("audit_writes_body", "file:"), ("debug_log", "log_or_stdio"), ("print", "log_or_stdio"),
    ("tempfile", "file_write:"),
])
def test_runtime_observer_catches_planted_raw_leak(observed, token, leak_variants, kind, expected):
    leak_variants(kind)
    leaks = observed(token)
    assert any(item.startswith(expected) for item in leaks), leaks


# ── 커밋 경계(보조): 감사 DB·캡처물은 git 무시 대상, 추적 0 ──────────────────────

@pytest.mark.parametrize("path", ["var/audit.sqlite3", "var/other.db", "elsewhere.sqlite3", "captures/x.har",
                                  "traffic/raw.bin", "dump.har", ".env"])
def test_audit_db_and_capture_paths_are_git_ignored(path):
    r = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=REPO_ROOT)
    assert r.returncode == 0, path


def test_no_audit_db_or_capture_is_tracked():
    tracked = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True,
                             check=True).stdout.splitlines()
    bad = [t for t in tracked if t.startswith(("var/", "captures/", "traffic/")) or
           t.endswith((".sqlite3", ".db", ".har", ".pcap", ".saz", ".burp"))]
    assert bad == []
