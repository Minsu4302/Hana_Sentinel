"""pyproject [project].dependencies(단일 출처)를 그대로 pip install — 런타임 의존성 목록 중복 방지."""
from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

deps = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
deps = deps["project"]["dependencies"]
if deps:
    subprocess.check_call([sys.executable, "-m", "pip", "install", *deps])
