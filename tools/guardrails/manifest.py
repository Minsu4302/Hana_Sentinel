"""manifest 파생기 — guardrails.yaml(SSOT) → capability manifest 생성물.

(A) §3.1 `manifest_derivation`. 생성 전에 레지스트리를 fail-closed로 검증하며,
하나라도 어긋나면 manifest를 만들지 않는다(enforced인데 검증 테스트 없음 → 생성 거부 등).
출력은 결정적(타임스탬프·해시 없음)이라 커밋된 생성물과 재파생 결과를 문자 단위로 비교할 수 있다.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.guardrails.registry import Entry, validate
from tools.guardrails.spec import Spec

MANIFEST_SCHEMA_VERSION = "1"


def effective_state(entry: Entry, by_id: dict[str, Entry]) -> str:
    """derived는 자체 강제가 없다 — 하위 키가 전부 enforced일 때만 enforced, 아니면 not_implemented."""
    status = entry["week1_status"]
    if status["state"] != "derived":
        return status["state"]
    children = [by_id[c]["week1_status"]["state"] for c in status["derived_from"]]
    return "enforced" if all(s == "enforced" for s in children) else "not_implemented"


def derive_manifest(entries: list[Entry], spec: Spec, root: Path) -> dict[str, Any]:
    validate(entries, spec, root)
    by_id = {e["id"]: e for e in entries}
    capabilities: dict[str, Any] = {}
    for e in entries:
        s = e["week1_status"]
        cap: dict[str, Any] = {"status": s["state"], "effective_status": effective_state(e, by_id)}
        for k in ("target", "note", "derived_from"):
            if k in s:
                cap[k] = s[k]
        cap["verification_tests"] = list(e["verification_tests"])
        capabilities[e["manifest_key"]] = cap
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "notice": "생성물 — 손으로 편집 금지. `make manifest`로 guardrails.yaml에서 재파생한다.",
        "source": "guardrails.yaml",
        "spec": f"docs/design-decision.md §3 매핑표 {spec.version}",
        "capabilities": capabilities,
    }


def render_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
