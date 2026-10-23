"""`engine_burp_isolation`(N4) · `no_autonomous_send`(N2) — 엔진 패키지 정적 import 경계.

'정상 통과'만이 아니라 '위조 거부'로 증명한다: 금지 import를 심은 더미 엔진(임시 디렉터리에만 생성)을
검사가 잡아내고, 금지 아닌 import만 가진 대조군 더미와 실제 엔진은 통과한다.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.arch_boundary import BURP, DYNAMIC, SEND, BoundaryScanError, scan_package, scan_source
from tools.guardrails import REPO_ROOT

ENGINE_ROOT = REPO_ROOT / "src" / "sentinel"

BURP_IMPORTS = [
    "import burp",
    "from burp import IBurpExtender",
    "import montoya.api",
    "from burp.api.montoya import MontoyaApi",
    "import portswigger.burp as pb",
    "import importlib\nimportlib.import_module('burp.api.montoya')",
    "__import__('montoya')",
    "def later():\n    import burp\n",
    "try:\n    import montoya\nexcept ImportError:\n    montoya = None\n",
]

SEND_IMPORTS = [
    "import socket",
    "from socket import create_connection",
    "import ssl",
    "import http.client",
    "from http import client",
    "from http.client import HTTPSConnection",
    "import http\nconn = http.client.HTTPConnection",
    "from urllib.request import urlopen",
    "import urllib.request as r",
    "from urllib import request",
    "import requests",
    "import httpx",
    "from aiohttp import ClientSession",
    "import urllib3",
    "import smtplib",
    "import xmlrpc.client",
    "from asyncio import open_connection",
    "from asyncio import *",
    "import asyncio\nasyncio.open_connection",
    "import asyncio as aio\naio.start_server",
    "import importlib\nimportlib.import_module('socket')",
    "__import__('http.client')",
]

DYNAMIC_ESCAPES = [
    "import importlib\nname = 'sock' + 'et'\nimportlib.import_module(name)",
    "__import__(name)",
    "exec('import socket')",
    "eval('__import__(\"socket\")')",
]

ALLOWED_IMPORTS = """\
import json
import re
import uuid
from dataclasses import dataclass
from http import HTTPStatus
import urllib.parse
from urllib.parse import urlsplit
import asyncio
from asyncio import gather
from . import sibling
"""


def _engine(tmp_path: Path, files: dict[str, str]) -> Path:
    """임시 디렉터리에 더미 엔진 패키지를 만든다(레포 밖 — 실제 엔진에 금지 코드를 두지 않음)."""
    root = tmp_path / "dummy_engine"
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return root


# ── 정상: 실제 엔진 ──────────────────────────────────────────────

def test_engine_package_has_no_burp_or_montoya_imports():
    assert [v for v in scan_package(ENGINE_ROOT) if v.kind == BURP] == []


def test_engine_package_has_no_send_or_socket_imports():
    assert [v for v in scan_package(ENGINE_ROOT) if v.kind in (SEND, DYNAMIC)] == []


def test_allowed_imports_pass_as_control(tmp_path):
    """대조군: 검사가 '무엇이든 실패시키는 가짜 차단'이 아님."""
    root = _engine(tmp_path, {"__init__.py": "", "ok.py": ALLOWED_IMPORTS})
    assert scan_package(root) == []


# ── 위조 거부: 금지 import를 심은 더미 ──────────────────────────────

@pytest.mark.parametrize("src", BURP_IMPORTS)
def test_rejects_planted_burp_import(tmp_path, src):
    root = _engine(tmp_path, {"__init__.py": "", "planted.py": src + "\n"})
    assert {v.kind for v in scan_package(root)} == {BURP}


@pytest.mark.parametrize("src", SEND_IMPORTS)
def test_rejects_planted_send_or_socket_import(tmp_path, src):
    root = _engine(tmp_path, {"__init__.py": "", "planted.py": src + "\n"})
    assert {v.kind for v in scan_package(root)} == {SEND}


@pytest.mark.parametrize("src", DYNAMIC_ESCAPES)
def test_rejects_statically_unverifiable_dynamic_import(tmp_path, src):
    root = _engine(tmp_path, {"__init__.py": "", "planted.py": src + "\n"})
    assert DYNAMIC in {v.kind for v in scan_package(root)}


def test_rejects_planted_import_in_nested_subpackage(tmp_path):
    root = _engine(tmp_path, {
        "__init__.py": "",
        "ok.py": ALLOWED_IMPORTS,
        "deep/__init__.py": "",
        "deep/deeper/__init__.py": "",
        "deep/deeper/hidden.py": "import json\nfrom burp import IBurpExtender\nimport socket\n",
    })
    found = scan_package(root)
    assert {v.kind for v in found} == {BURP, SEND}
    assert all(v.path.endswith("hidden.py") for v in found)
    assert {v.line for v in found} == {2, 3}


# ── 위조 거부: 검사 자체가 비거나 깨지면 통과가 아님(fail-closed) ─────────

def test_empty_or_missing_package_is_an_error_not_a_pass(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(BoundaryScanError):
        scan_package(tmp_path / "empty")
    with pytest.raises(BoundaryScanError):
        scan_package(tmp_path / "does_not_exist")


def test_unparseable_source_is_an_error_not_a_pass():
    with pytest.raises(BoundaryScanError):
        scan_source("broken.py", "import socket\ndef (:\n")
