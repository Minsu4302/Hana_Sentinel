"""LLM 호출 감사 — (A) §2.8 `llm_io_audit`, §3.3 `audit_write_failure`. 지문만 남긴다: 입력 뷰·원출력의 SHA-256, 크기, 소요 시간, 결과,
prompt_version, model_id. 내용은 남기지 않는다(보존은 저장 설계 D5). 기록에 실패하면 False — 호출자가 LLM 결과를 폐기한다.
"""
from __future__ import annotations

import hashlib

from sentinel import audit


def _fingerprint(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def audit_llm_call(view: str, output: bytes, elapsed_ms: int, llm_outcome: str, prompt_version: str, model_id: str) -> bool:
    view_hash, view_bytes = _fingerprint(view.encode("utf-8"))
    output_hash, output_bytes = _fingerprint(output)
    return audit.write_required(f"llm_call view_sha256={view_hash} view_bytes={view_bytes} output_sha256={output_hash} "
                                f"output_bytes={output_bytes} elapsed_ms={elapsed_ms} outcome={llm_outcome} "
                                f"prompt_version={prompt_version} model_id={model_id}")
