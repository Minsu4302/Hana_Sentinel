"""제품 런타임 의존성의 외부 송신 라이브러리 검사(전이 포함).

(A) §3.1 `egress_static_check` — "외부 HTTP 송신 의존성 0". W1-01 `no_autonomous_send`가 엔진 소스의
직접 import만 보는 한계(전이 의존성)를 이어받는다: pyproject의 [project].dependencies에서 시작해
설치된 배포판 메타데이터(Requires-Dist)를 따라 전이 폐포를 만들고, 송신 라이브러리가 하나라도 있으면 검출.
extra·환경 marker는 실제로 요청된 extra 기준으로 평가한다.
의존성의 메타데이터를 찾을 수 없으면 폐포를 확정할 수 없으므로 '검출 없음'이 아니라 오류(fail-closed).

한계(정직 표기): 아래 목록에 있는 배포판만 검출한다(목록 = 정책). 송신 기능을 내장한 미등재 패키지,
메타데이터에 의존성을 선언하지 않고 내부에 벤더링한 코드는 잡지 못한다. 개발 도구 의존성
(requirements-dev.txt)은 제품 런타임이 아니므로 범위 밖.
"""
from __future__ import annotations

import re
import tomllib
from collections import deque
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Callable

from packaging.requirements import InvalidRequirement, Requirement

# 외부 HTTP/네트워크 송신 클라이언트 + 상용 AI SDK(N1). 정규화된 배포판 이름.
EGRESS_DISTRIBUTIONS = frozenset({
    "requests", "httpx", "httpcore", "aiohttp", "urllib3", "httplib2", "pycurl", "treq",
    "websocket-client", "grpcio", "boto3", "botocore", "google-api-python-client",
    "openai", "anthropic", "google-generativeai", "google-genai", "cohere", "mistralai",
    "litellm", "langchain", "langchain-core", "langchain-community", "langchain-openai",
    "llama-index", "together", "groq", "replicate",
    # 원격 측정 송신(OpenTelemetry exporter·distro). `opentelemetry-api` 자체는 송신하지 않음 —
    # fastapi가 필수 의존성으로 끌어오므로 허용하되, 실제로 내보내는 계열은 금지.
    "opentelemetry-exporter-otlp", "opentelemetry-exporter-otlp-proto-grpc",
    "opentelemetry-exporter-otlp-proto-http", "opentelemetry-exporter-zipkin",
    "opentelemetry-exporter-zipkin-json", "opentelemetry-exporter-jaeger",
    "opentelemetry-exporter-prometheus-remote-write", "opentelemetry-distro",
    "sentry-sdk", "ddtrace",
})

RequiresOf = Callable[[str], "list[str] | None"]


class DependencyScanError(RuntimeError):
    """전이 폐포를 확정할 수 없음 — 통과로 취급하지 않는다."""


@dataclass(frozen=True)
class EgressDependency:
    name: str
    chain: tuple[str, ...]  # 선언 의존성 → … → 송신 라이브러리

    def render(self) -> str:
        return f"[egress_dependency] {self.name} (경로: {' → '.join(self.chain)})"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_dependencies(pyproject: Path) -> list[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies")
    if not isinstance(deps, list):
        raise DependencyScanError("pyproject [project].dependencies가 목록이 아님")
    return deps


def installed_requires(name: str) -> list[str] | None:
    try:
        return list(metadata.distribution(name).requires or [])
    except metadata.PackageNotFoundError:
        return None


def _applies(req: Requirement, extras: frozenset[str]) -> bool:
    if req.marker is None:
        return True
    return any(req.marker.evaluate({"extra": e}) for e in (extras | {""}))


def find_egress_dependencies(declared: list[str], requires_of: RequiresOf = installed_requires
                             ) -> list[EgressDependency]:
    found: list[EgressDependency] = []
    seen: set[tuple[str, frozenset[str]]] = set()
    queue: deque[tuple[str, tuple[str, ...]]] = deque((d, ()) for d in declared)
    while queue:
        spec, chain = queue.popleft()
        try:
            req = Requirement(spec)
        except InvalidRequirement as exc:
            raise DependencyScanError(f"해석 불가 의존성 표기 {spec!r}") from exc
        name, extras = normalize(req.name), frozenset(normalize(e) for e in req.extras)
        path = chain + (name,)
        if name in EGRESS_DISTRIBUTIONS:
            found.append(EgressDependency(name, path))
            continue
        if (name, extras) in seen:
            continue
        seen.add((name, extras))
        requires = requires_of(name)
        if requires is None:
            raise DependencyScanError(f"{' → '.join(path)}: 메타데이터 없음 — 전이 폐포 확정 불가")
        for sub in requires:
            try:
                sub_req = Requirement(sub)
            except InvalidRequirement as exc:
                raise DependencyScanError(f"{name}: 해석 불가 하위 의존성 {sub!r}") from exc
            if _applies(sub_req, extras):
                queue.append((sub, path))
    return found
