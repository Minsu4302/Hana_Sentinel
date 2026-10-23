"""manifest 스냅샷 — ExecutionResponse에 동봉할 현재 보호 상태((A) §2.5).

커밋된 manifest 생성물(`manifest/capability_manifest.json`, `guardrails.yaml`에서 파생)을 읽어
키별 `status`·`effective_status`만 담은 스냅샷을 만든다. 결과가 '없는 보호를 있는 척' 못 하게 하는
manifest 정직성의 런타임 구현이다. 파일이 없거나 구조가 깨졌으면 스냅샷을 만들지 않는다 →
서버 기동 거부(fail-closed: 정직성을 보증할 수 없는 상태로 응답하지 않는다).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

MANIFEST_ENV: Final = "SENTINEL_MANIFEST"
DEFAULT_MANIFEST: Final = Path(__file__).resolve().parents[2] / "manifest" / "capability_manifest.json"
_STATES: Final = frozenset({"enforced", "not_implemented", "disabled", "unverifiable", "derived"})


class ManifestError(RuntimeError):
    """manifest를 읽을 수 없음 — 기동 거부."""


def manifest_path(environ: dict[str, str] | None = None) -> Path:
    value = (os.environ if environ is None else environ).get(MANIFEST_ENV)
    return Path(value) if value else DEFAULT_MANIFEST


def load_manifest_snapshot(path: Path | None = None) -> dict[str, Any]:
    path = manifest_path() if path is None else path
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(f"manifest를 읽을 수 없음: {path.name}") from exc
    caps = doc.get("capabilities") if isinstance(doc, dict) else None
    if not isinstance(caps, dict) or not caps or not isinstance(doc.get("spec"), str):
        raise ManifestError("manifest 구조 오류(capabilities·spec)")
    snapshot: dict[str, Any] = {}
    for key, cap in caps.items():
        status = cap.get("status") if isinstance(cap, dict) else None
        effective = cap.get("effective_status") if isinstance(cap, dict) else None
        if status not in _STATES or effective not in _STATES - {"derived"}:
            raise ManifestError(f"manifest 상태값 오류: {key}")
        snapshot[key] = {"status": status, "effective_status": effective}
    return {"schema_version": doc.get("schema_version"), "spec": doc["spec"], "capabilities": snapshot}
