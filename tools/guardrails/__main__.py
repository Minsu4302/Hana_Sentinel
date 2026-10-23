"""CLI: python -m tools.guardrails {sync|manifest|check}

- sync     : (A) §3 → guardrails.yaml 재파생(enforced 승격만 보존)
- manifest : guardrails.yaml → manifest 생성물 (검증 실패 시 생성 거부)
- check    : 쓰지 않고 검증만 — 레지스트리 정합 + 두 생성물이 재파생 결과와 일치하는지
"""
from __future__ import annotations

import sys
from pathlib import Path

from tools.guardrails import MANIFEST_PATH, REGISTRY_PATH, REPO_ROOT, SPEC_PATH
from tools.guardrails.manifest import derive_manifest, render_manifest
from tools.guardrails.registry import RegistryError, load_registry, render_yaml, sync, validate
from tools.guardrails.spec import SpecError, load_spec


def _read(path: Path) -> str | None:
    # universal newline 읽기 — 체크아웃 줄바꿈(CRLF/LF)과 무관하게 내용만 비교
    return path.read_text(encoding="utf-8") if path.is_file() else None


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("sync", "manifest", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[0]
    try:
        spec = load_spec(SPEC_PATH)
        current = load_registry(REGISTRY_PATH) if REGISTRY_PATH.is_file() else []
        if cmd == "sync":
            entries = sync(spec, current)
            validate(entries, spec, REPO_ROOT)
            _write(REGISTRY_PATH, render_yaml(entries, spec))
            print(f"guardrails.yaml 파생 완료 ({len(entries)}키)")
            return 0
        manifest_text = render_manifest(derive_manifest(current, spec, REPO_ROOT))
        if cmd == "manifest":
            _write(MANIFEST_PATH, manifest_text)
            print(f"manifest 생성 완료: {MANIFEST_PATH.relative_to(REPO_ROOT)}")
            return 0
    except (SpecError, RegistryError) as exc:
        print(f"guardrails {cmd}: 거부\n{exc}", file=sys.stderr)
        return 1

    # check
    problems = []
    if _read(REGISTRY_PATH) != render_yaml(sync(spec, current), spec):
        problems.append("guardrails.yaml ≠ (A) §3 재파생 — `make guardrails-sync` 후 diff를 검토")
    if _read(MANIFEST_PATH) != manifest_text:
        problems.append("manifest 생성물 ≠ guardrails.yaml 재파생 — 손 편집 금지, `make manifest`")
    for p in problems:
        print(f"guardrails check: {p}", file=sys.stderr)
    if not problems:
        print("guardrails check: 통과")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
