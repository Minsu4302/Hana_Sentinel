"""LLM 경로 — (A) §2.8, §3.1 `llm_adapter_no_target_resend`. 어댑터를 부르는 유일한 곳이다.

③을 통과한 스냅샷 → 입력 뷰 → 어댑터 → 응답 해석 → `LlmRun`. 판정은 하지 않는다 — 초안은 ④의 게이트로만 간다.
재시도는 없다(v1 — 다시 생성하면 J2를 가린다). 설정이 없으면 rule_llm으로 기동하지 않는다(기본 rule_only).
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Final

from sentinel import strict_json
from sentinel.pipeline import llm_adapter, llm_prompt
from sentinel.pipeline.execution import LlmRun
from sentinel.pipeline.output_gate import LlmFailure
from sentinel.pipeline.sanitization_check import SanitizedEnvelope

MODE_ENV: Final = "SENTINEL_PIPELINE_MODE"
PORT_ENV: Final = "SENTINEL_LLM_PORT"
MODEL_ENV: Final = "SENTINEL_LLM_MODEL_ID"
MODEL_ID: Final = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
# 모델별 예산(§6.2 선별 — 실측 속도로 다시 도출). 없으면 Limits 기본값. 값은 묶음 해시에 그대로 들어간다. 출처는 progress-log에 남긴다.
BUDGET_ENV: Final = {"view_bytes": ("SENTINEL_LLM_VIEW_BYTES", 512, 65536),
                     "max_tokens": ("SENTINEL_LLM_MAX_TOKENS", 16, 8192),
                     "deadline_seconds": ("SENTINEL_LLM_DEADLINE_SECONDS", 10, 3600)}

# (A) §2.8 사유 대응표. 어댑터 사유를 더하면 이 표부터 정한다.
FAILURE_OF: Final = {
    "api_key_missing": "unavailable",
    "connect_failed": "unavailable",
    "bad_status": "unavailable",
    "transport_error": "unavailable",
    "io_timeout": "timeout",
    "deadline_exceeded": "timeout",
    "response_too_large": "oversize",
}


class LlmConfigError(ValueError):
    """rule_llm 설정이 없거나 잘못됐다 — 기동 거부. 사유 코드만 담는다."""


@dataclass(frozen=True)
class LlmConfig:
    model_id: str
    port: int
    limits: llm_adapter.Limits = field(default_factory=llm_adapter.Limits)

    @property
    def prompt_version(self) -> str:
        limits = self.limits
        return llm_prompt.prompt_version(temperature=limits.temperature, max_tokens=limits.max_tokens, view_bytes=limits.view_bytes,
                                         deadline_seconds=limits.deadline_seconds)


def _budget() -> llm_adapter.Limits:
    values: dict[str, int] = {}
    for field_name, (env, low, high) in BUDGET_ENV.items():
        text = os.environ.get(env)
        if text is None:
            continue
        if not (text.isascii() and text.isdigit() and low <= int(text) <= high):
            raise LlmConfigError("llm_budget_invalid")
        values[field_name] = int(text)
    if "deadline_seconds" in values:  # 비스트리밍 응답이라 읽기 한 번의 상한도 전체 기한과 같다
        values["io_timeout_seconds"] = values["deadline_seconds"]
    return llm_adapter.Limits(**values)


def config_from_env() -> LlmConfig | None:
    """None이면 rule_only다. rule_llm을 달라고 했는데 설정이 모자라면 조용히 rule_only로 내려가지 않고 거부한다."""
    mode = os.environ.get(MODE_ENV, "rule_only")
    if mode == "rule_only":
        return None
    if mode != "rule_llm":
        raise LlmConfigError("pipeline_mode_unknown")
    port, model_id = os.environ.get(PORT_ENV, ""), os.environ.get(MODEL_ENV, "")
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise LlmConfigError("llm_port_invalid")
    if not MODEL_ID.fullmatch(model_id):
        raise LlmConfigError("llm_model_id_invalid")
    if not llm_adapter.api_key_present():
        raise LlmConfigError("llm_api_key_missing")
    return LlmConfig(model_id=model_id, port=int(port), limits=_budget())


def parsed_completion(body: bytes) -> str | LlmFailure:
    """추론 서버 응답 → 초안 문자열. 스키마 판정은 게이트 몫이고 여기서는 JSON인지까지만 본다(§2.8 파싱 실패 → unparseable)."""
    try:
        choice = json.loads(body)["choices"][0]
        finish_reason, content = choice["finish_reason"], choice["message"]["content"]
    except (ValueError, RecursionError, KeyError, IndexError, TypeError):
        return LlmFailure("unparseable")
    if finish_reason == "length":
        return LlmFailure("truncated")
    if not isinstance(content, str):
        return LlmFailure("unparseable")
    try:
        strict_json.parse(content)
    except ValueError:
        return LlmFailure("unparseable")
    return content


def run(sanitized: SanitizedEnvelope, config: LlmConfig) -> LlmRun:
    payload, view_truncated = llm_adapter.llm_input(sanitized, config.limits)
    started = time.monotonic()
    reply = llm_adapter.complete(payload, config.port, llm_prompt.TRANSMISSION_SCHEMA, config.limits)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    failed = isinstance(reply, llm_adapter.AdapterFailure)
    return LlmRun(model_id=config.model_id, prompt_version=config.prompt_version,
                  output=LlmFailure(FAILURE_OF[reply.reason]) if failed else parsed_completion(reply), view=payload.content,
                  elapsed_ms=elapsed_ms, view_truncated=view_truncated, raw_output=b"" if failed else reply)
