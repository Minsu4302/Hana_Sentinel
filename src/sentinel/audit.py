"""감사 저장 — `sentinel.audit` 로거 → SQLite. (A) §3.3 `audit_log_present`.

감사 지점(토큰 게이트·스키마 게이트·재검증·요청 크기·egress 시도)은 모두 `sentinel.audit` 로거에 사유 코드·
구조 위치만 담은 메시지를 남긴다. 이 모듈은 그 메시지를 로컬 SQLite 파일(기본 `var/audit.sqlite3`,
환경변수 `SENTINEL_AUDIT_DB`로 변경)에 저장한다. 저장하는 것은 이미 위생 검사된 메시지 문자열뿐이며
본문·토큰·민감 원문·입력이 정한 이름은 들어가지 않는다(각 감사 지점의 위생 테스트 + 저장소 위생 테스트).

egress 시도 감사: 제품 코드에는 송신 코드가 없다(N1·N2). 그래도 런타임에 외부 목적지로의 소켓 연결·DNS 해석·
송신이 일어나면 Python 런타임 감사 훅(`sys.addaudithook`)으로 관측해 기록한다. **기록만 하고 차단하지 않는다**
— 운영 차단의 실주체는 OS/네트워크(`egress_enforcement_owner` = unverifiable). 목적지 호스트는 사내 정보일 수
있어 기록하지 않는다(동작 종류·포트만).

정직 표기: 감사 기록 *실패* 시 fail-closed(`audit_write_failure`)는 2주차다. 1주차는 '감사가 남는다'만 보장하며,
기록에 실패해도 요청 처리를 막지 않는다(logging의 handleError로 넘어감) — '못 남기면 거부'는 미정의.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from sentinel.egress_policy import Destination, classify_destination

AUDIT_DB_ENV: Final = "SENTINEL_AUDIT_DB"
DEFAULT_AUDIT_DB: Final = Path("var") / "audit.sqlite3"

audit_log = logging.getLogger("sentinel.audit")

_SCHEMA = """CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    event TEXT NOT NULL,
    message TEXT NOT NULL
)"""


class SQLiteAuditHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__(level=logging.INFO)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute(_SCHEMA)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            with self._lock:
                self._conn.execute(
                    "INSERT INTO audit_events (ts, level, event, message) VALUES (?, ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), record.levelname, message.split(" ", 1)[0], message))
        except Exception:  # noqa: BLE001 — 1주차: 기록 실패가 요청을 막지 않음(audit_write_failure = 2주차)
            self.handleError(record)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
        super().close()


def audit_db_path(environ: dict[str, str] | None = None) -> Path:
    value = (os.environ if environ is None else environ).get(AUDIT_DB_ENV)
    return Path(value) if value else DEFAULT_AUDIT_DB


def attach_audit_store(path: Path) -> SQLiteAuditHandler:
    handler = SQLiteAuditHandler(path)
    audit_log.addHandler(handler)
    audit_log.setLevel(logging.INFO)
    return handler


def detach_audit_store(handler: SQLiteAuditHandler) -> None:
    audit_log.removeHandler(handler)
    handler.close()


def read_audit_events(path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("SELECT ts, level, event, message FROM audit_events ORDER BY id").fetchall()
    finally:
        conn.close()
    return [dict(zip(("ts", "level", "event", "message"), r)) for r in rows]


# ── egress 시도 감사 훅 ─────────────────────────────────────────────

_EGRESS_EVENTS: Final = {"socket.connect": "connect", "socket.getaddrinfo": "resolve", "socket.sendto": "sendto"}
_hook_state = threading.local()
_hook_installed = False


def _egress_audit_hook(event: str, args: tuple[Any, ...]) -> None:
    op = _EGRESS_EVENTS.get(event)
    if op is None or getattr(_hook_state, "active", False):
        return
    try:
        if op == "resolve":
            host, port = args[0], args[1]
        else:
            address = args[1]
            if not (isinstance(address, tuple) and len(address) >= 2):
                return  # AF_UNIX 등 — 같은 호스트의 IPC
            host, port = address[0], address[1]
        if host is None or classify_destination(host) is Destination.LOCAL:
            return
        _hook_state.active = True  # 감사 기록 중 발생하는 감사 이벤트로의 재귀 방지
        audit_log.warning("egress_attempt op=%s port=%s", op, port if isinstance(port, int) else "<other>")
    except Exception:  # noqa: BLE001 — 감사 훅은 관측만; 훅 오류가 호출자를 깨지 않게
        return
    finally:
        _hook_state.active = False


def install_egress_audit_hook() -> None:
    """프로세스당 1회. 감사 훅은 제거할 수 없으므로 중복 설치를 막는다."""
    global _hook_installed
    if not _hook_installed:
        sys.addaudithook(_egress_audit_hook)
        _hook_installed = True
