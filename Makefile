# Sentinel Harness — 검증 진입점.
# merge 전 `make verify` 통과 필수. 단 종료코드 0 ≠ 1주차 완료 판정((B) §4: manifest 정직성 포함).
# 레시피는 sh·cmd 양쪽에서 돌도록 단순 명령만 쓴다.

ifneq ($(wildcard .venv/Scripts/python.exe),)
PYTHON ?= .venv/Scripts/python.exe
else ifneq ($(wildcard .venv/bin/python),)
PYTHON ?= .venv/bin/python
else
PYTHON ?= python
endif

export PYTHONUTF8 := 1
export PYTHONIOENCODING := utf-8

.PHONY: verify secret-scan guardrails-check test guardrails-sync manifest install-dev install-hooks serve

## verify: 시크릿 전수 스캔 → 가드레일 정합(guardrails.yaml↔(A) §3, manifest↔재파생) → pytest(+ enforced 검증 노드 수집·통과 자기검증)
verify: secret-scan guardrails-check test

secret-scan:
	$(PYTHON) tools/secret_scan.py --all

guardrails-check:
	$(PYTHON) -m tools.guardrails check

test:
	$(PYTHON) -m pytest -p tools.guardrails.selfcheck --manifest-selfcheck=guardrails.yaml

## guardrails-sync: (A) §3 → guardrails.yaml 재파생(enforced 승격만 보존). 결과 diff는 사람이 검토.
guardrails-sync:
	$(PYTHON) -m tools.guardrails sync

## manifest: guardrails.yaml → manifest 생성물 재생성(검증 실패 시 생성 거부)
manifest:
	$(PYTHON) -m tools.guardrails manifest

install-dev:
	$(PYTHON) tools/install_runtime_deps.py
	$(PYTHON) -m pip install -r requirements-dev.txt

## serve: 분석 서버 기동(127.0.0.1 고정, 바인드 주소 옵션 없음)
serve:
	$(PYTHON) -m sentinel.server

install-hooks:
	$(PYTHON) -m pre_commit install
